package remotedialer

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
)

var (
	errFailedAuth       = errors.New("failed authentication")
	errWrongMessageType = errors.New("wrong websocket message type")
)

type Authorizer func(req *http.Request) (clientKey string, authed bool, err error)
type ErrorWriter func(rw http.ResponseWriter, req *http.Request, code int, err error)

func DefaultErrorWriter(rw http.ResponseWriter, req *http.Request, code int, err error) {
	rw.WriteHeader(code)
	rw.Write([]byte(err.Error()))
}

type HandlerFunc func(ctx *Context)

type MiddleFunc func(next HandlerFunc) HandlerFunc

type Server struct {
	PeerID                  string
	PeerToken               string
	ClientConnectAuthorizer ConnectAuthorizer
	authorizer              Authorizer
	middleFunc              []MiddleFunc
	errorWriter             ErrorWriter
	sessions                *sessionManager
	peers                   map[string]peer
	peerLock                sync.Mutex
}

type Context struct {
	RW      http.ResponseWriter
	Req     *http.Request
	Session *Session
}

func New(auth Authorizer, errorWriter ErrorWriter, funcs ...MiddleFunc) *Server {
	s := &Server{
		peers:       map[string]peer{},
		authorizer:  auth,
		errorWriter: errorWriter,
		sessions:    newSessionManager(),
		middleFunc:  make([]MiddleFunc, 0),
	}
	s.WithMiddleFuncs(append([]MiddleFunc{s.authorizerMiddleFunc}, funcs...)...)
	return s
}

func (s *Server) WithMiddleFuncs(funcs ...MiddleFunc) {
	s.middleFunc = append(s.middleFunc, funcs...)
}

func (s *Server) authorizerMiddleFunc(next HandlerFunc) HandlerFunc {
	return func(ctx *Context) {
		clientKey, authed, peer, proxy, err := s.auth(ctx.Req)
		if err != nil {
			s.errorWriter(ctx.RW, ctx.Req, 400, err)
			return
		}
		if !authed {
			s.errorWriter(ctx.RW, ctx.Req, 401, errFailedAuth)
			return
		}

		logrus.Infof("Handling backend connection request [%s]", clientKey)

		upgrader := websocket.Upgrader{
			HandshakeTimeout: 5 * time.Second,
			CheckOrigin:      func(r *http.Request) bool { return true },
			Error:            s.errorWriter,
		}

		wsConn, err := upgrader.Upgrade(ctx.RW, ctx.Req, nil)
		if err != nil {
			s.errorWriter(ctx.RW, ctx.Req, 400, errors.Wrapf(err, "Error during upgrade for host [%v]", clientKey))
			return
		}
		var session *Session
		if !proxy {
			session = s.sessions.add(clientKey, wsConn, peer)
			defer s.sessions.remove(session)
		} else {
			session = NewProxySession(func(string, string) bool { return true }, wsConn)
			session.dialer = func(ctx context.Context, network, address string) (net.Conn, error) {
				parts := strings.SplitN(network, "::", 2)
				if len(parts) != 2 {
					return nil, fmt.Errorf("invalid clientKey/proto: %s", network)
				}
				d := s.Dialer(parts[0])
				return d(ctx, parts[1], address)
			}
			defer session.Close()
		}
		session.auth = s.ClientConnectAuthorizer
		ctx.Session = session

		next(ctx)
	}
}

func (s *Server) ServeHTTP(rw http.ResponseWriter, req *http.Request) {

	handle := func(ctx *Context) {
		if ctx.Session == nil {
			logrus.Infof("No Session found for request [%s]", ctx.Req.URL.Path)
			return
		}
		code, err := ctx.Session.Serve(req.Context())
		if err != nil {
			// Hijacked so we can't write to the client
			logrus.Infof("error in remotedialer server [%d]: %v", code, err)
		}
	}

	for _, f := range s.middleFunc {
		handle = f(handle)
	}

	ctx := &Context{
		RW:  rw,
		Req: req,
	}

	handle(ctx)
}

func (s *Server) auth(req *http.Request) (clientKey string, authed, peer, proxy bool, err error) {
	id := req.Header.Get(ID)
	token := req.Header.Get(Token)
	isProxy := req.Header.Get(Proxy)
	if id != "" && token != "" {
		// peer authentication
		s.peerLock.Lock()
		p, ok := s.peers[id]
		s.peerLock.Unlock()

		if ok && p.token == token {
			return id, true, true, false, nil
		}
	}
	id, authed, err = s.authorizer(req)
	if id != "" && isProxy != "" {
		return id, true, false, true, nil
	}
	return id, authed, false, false, err
}
