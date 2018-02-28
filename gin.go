// Copyright 2014 Manu Martinez-Almeida.  All rights reserved.
// Use of this source code is governed by a MIT style
// license that can be found in the LICENSE file.

package gin

import (
	"html/template"
	"net"
	"net/http"
	"os"
	"sync"

	"github.com/gin-gonic/gin/render"
)

const (
	// Version is Framework's version.
	Version                = "v1.2"
	defaultMultipartMemory = 32 << 20 // 32 MB
)

var (
	default404Body   = []byte("404 page not found")
	default405Body   = []byte("405 method not allowed")
	defaultAppEngine bool
)

type HandlerFunc func(*Context)
type HandlersChain []HandlerFunc

// Last返回链中最后一个处理程序。即。最后的处理程序是主要的处理程序。
func (c HandlersChain) Last() HandlerFunc {
	if length := len(c); length > 0 {
		return c[length-1]
	}
	return nil
}

type RouteInfo struct {
	Method  string
	Path    string
	Handler string
}

type RoutesInfo []RouteInfo

// Engine是框架的实例，它包含muxer，中间件和配置设置。
//使用New（）或Default（）创建引擎的实例
type Engine struct {
	RouterGroup

	//如果当前路线不能匹配，则启用自动重定向
	//存在（不带）尾部斜杠的路径处理程序。
	//例如，如果/ foo /被请求但是一个路由只存在于/ foo中，那么
	//用GET请求的http状态码301将客户端重定向到/ foo
	//和其他所有请求方法的307。
	RedirectTrailingSlash bool

	//如果启用，则路由器尝试修复当前的请求路径，如果不是
	//处理已注册。
	//第一个多余的路径元素，如../或//被删除。
	//之后，路由器对清理后的路径进行不区分大小写的查找。
	//如果可以找到该路由的句柄，则路由器进行重定向
	//到GET请求的状态码301和307的正确路径
	//所有其他请求方法。
	//例如/ FOO和/..//Foo可以被重定向到/ foo。
	// RedirectTrailingSlash独立于此选项。
	RedirectFixedPath bool

	//如果启用，路由器会检查是否允许其他方法
	//当前路由，如果当前请求无法路由。
	//如果是这种情况，请求将以'方法不允许'
	//和HTTP状态码405。
	//如果没有其他方法被允许，请求被委托给NotFound
	//处理程序。
	HandleMethodNotAllowed bool
	ForwardedByClientIP    bool

	//＃726＃755如果启用，它将会启动一些标题
	// 'X-AppEngine ...'以更好地与该PaaS集成。
	AppEngine bool

	//如果启用，则会使用url.RawPath来查找参数。
	UseRawPath bool

	//如果为true，则路径值将不转义。
	//如果UseRawPath为false（默认），则UnescapePathValues有效，
	//作为url.Path将会被使用，这已经是非转义的。
	UnescapePathValues bool

	//赋给http.Request的ParseMultipartForm的'maxMemory'参数的值
	//方法调用。
	MaxMultipartMemory int64

	delims           render.Delims
	secureJsonPrefix string
	HTMLRender       render.HTMLRender
	FuncMap          template.FuncMap
	allNoRoute       HandlersChain
	allNoMethod      HandlersChain
	noRoute          HandlersChain
	noMethod         HandlersChain
	pool             sync.Pool
	trees            methodTrees
}

var _ IRouter = &Engine{}

// New返回一个没有附加任何中间件的新的空白引擎实例。
//默认情况下，配置是：
// - RedirectTrailingSlash:  true
// - RedirectFixedPath:      false
// - HandleMethodNotAllowed: false
// - ForwardedByClientIP:    true
// - UseRawPath:             false
// - UnescapePathValues:     true
func New() *Engine {
	debugPrintWARNINGNew()
	engine := &Engine{
		RouterGroup: RouterGroup{
			Handlers: nil,
			basePath: "/",
			root:     true,
		},
		FuncMap:                template.FuncMap{},
		RedirectTrailingSlash:  true,
		RedirectFixedPath:      false,
		HandleMethodNotAllowed: false,
		ForwardedByClientIP:    true,
		AppEngine:              defaultAppEngine,
		UseRawPath:             false,
		UnescapePathValues:     true,
		MaxMultipartMemory:     defaultMultipartMemory,
		trees:                  make(methodTrees, 0, 9),
		delims:                 render.Delims{Left: "{{", Right: "}}"},
		secureJsonPrefix:       "while(1);",
	}
	engine.RouterGroup.engine = engine
	engine.pool.New = func() interface{} {
		return engine.allocateContext()
	}
	return engine
}

//默认返回一个引擎实例，Logger和Recovery中间件已经连接。
func Default() *Engine {
	debugPrintWARNINGDefault()
	engine := New()
	engine.Use(Logger(), Recovery())
	return engine
}

func (engine *Engine) allocateContext() *Context {
	return &Context{engine: engine}
}

func (engine *Engine) Delims(left, right string) *Engine {
	engine.delims = render.Delims{Left: left, Right: right}
	return engine
}

// SecureJsonPrefix设置Context.SecureJSON中使用的secureJsonPrefix。
func (engine *Engine) SecureJsonPrefix(prefix string) *Engine {
	engine.secureJsonPrefix = prefix
	return engine
}

// LoadHTMLGlob加载由glob模式标识的HTML文件
//并将结果与​​HTML呈现器相关联。
func (engine *Engine) LoadHTMLGlob(pattern string) {
	left := engine.delims.Left
	right := engine.delims.Right

	if IsDebugging() {
		debugPrintLoadTemplate(template.Must(template.New("").Delims(left, right).Funcs(engine.FuncMap).ParseGlob(pattern)))
		engine.HTMLRender = render.HTMLDebug{Glob: pattern, FuncMap: engine.FuncMap, Delims: engine.delims}
		return
	}

	templ := template.Must(template.New("").Delims(left, right).Funcs(engine.FuncMap).ParseGlob(pattern))
	engine.SetHTMLTemplate(templ)
}

// LoadHTMLFiles加载一段HTML文件
//并将结果与​​HTML呈现器相关联。
func (engine *Engine) LoadHTMLFiles(files ...string) {
	if IsDebugging() {
		engine.HTMLRender = render.HTMLDebug{Files: files, FuncMap: engine.FuncMap, Delims: engine.delims}
		return
	}

	templ := template.Must(template.New("").Delims(engine.delims.Left, engine.delims.Right).Funcs(engine.FuncMap).ParseFiles(files...))
	engine.SetHTMLTemplate(templ)
}

// SetHTMLTemplate将模板与HTML渲染器关联。
func (engine *Engine) SetHTMLTemplate(templ *template.Template) {
	if len(engine.trees) > 0 {
		debugPrintWARNINGSetHTMLTemplate()
	}

	engine.HTMLRender = render.HTMLProduction{Template: templ.Funcs(engine.FuncMap)}
}

// SetFuncMap设置用于template.FuncMap的FuncMap。
func (engine *Engine) SetFuncMap(funcMap template.FuncMap) {
	engine.FuncMap = funcMap
}

// NoRoute为NoRoute添加处理程序。它默认返回404代码。
func (engine *Engine) NoRoute(handlers ...HandlerFunc) {
	engine.noRoute = handlers
	engine.rebuild404Handlers()
}

// NoMethod设置处理程序调用when ... TODO。
func (engine *Engine) NoMethod(handlers ...HandlerFunc) {
	engine.noMethod = handlers
	engine.rebuild405Handlers()
}

//使用将全局中间件附加到路由器。即。通过Use（）附加的中间件将会是
//包含在每个请求的处理程序链中。即使404,405，静态文件...
//例如，这是记录器或错误管理中间件的正确位置。
func (engine *Engine) Use(middleware ...HandlerFunc) IRoutes {
	engine.RouterGroup.Use(middleware...)
	engine.rebuild404Handlers()
	engine.rebuild405Handlers()
	return engine
}

func (engine *Engine) rebuild404Handlers() {
	engine.allNoRoute = engine.combineHandlers(engine.noRoute)
}

func (engine *Engine) rebuild405Handlers() {
	engine.allNoMethod = engine.combineHandlers(engine.noMethod)
}

func (engine *Engine) addRoute(method, path string, handlers HandlersChain) {
	assert1(path[0] == '/', "path must begin with '/'")
	assert1(method != "", "HTTP method can not be empty")
	assert1(len(handlers) > 0, "there must be at least one handler")

	debugPrintRoute(method, path, handlers)
	root := engine.trees.get(method)
	if root == nil {
		root = new(node)
		engine.trees = append(engine.trees, methodTree{method: method, root: root})
	}
	root.addRoute(path, handlers)
}

//路由返回一段注册路由，包括一些有用的信息，例如：
// http方法，路径和处理程序名称。
func (engine *Engine) Routes() (routes RoutesInfo) {
	for _, tree := range engine.trees {
		routes = iterate("", tree.method, routes, tree.root)
	}
	return routes
}

func iterate(path, method string, routes RoutesInfo, root *node) RoutesInfo {
	path += root.path
	if len(root.handlers) > 0 {
		routes = append(routes, RouteInfo{
			Method:  method,
			Path:    path,
			Handler: nameOfFunction(root.handlers.Last()),
		})
	}
	for _, child := range root.children {
		routes = iterate(path, method, routes, child)
	}
	return routes
}

//运行将路由器连接到http.Server并开始监听并提供HTTP请求。
//这是http.ListenAndServe（addr，router）的快捷方式，
//注意：除非发生错误，否则此方法将无限期地阻止调用goroutine。
func (engine *Engine) Run(addr ...string) (err error) {
	defer func() { debugPrintError(err) }()

	address := resolveAddress(addr)
	debugPrint("Listening and serving HTTP on %s\n", address)
	err = http.ListenAndServe(address, engine)
	return
}

// RunTLS将路由器连接到http.Server，并开始监听并提供HTTPS（安全）请求。
//它是http.ListenAndServeTLS（addr，certFile，keyFile，路由器）的快捷方式，
//注意：除非发生错误，否则此方法将无限期地阻止调用goroutine。
func (engine *Engine) RunTLS(addr, certFile, keyFile string) (err error) {
	debugPrint("Listening and serving HTTPS on %s\n", addr)
	defer func() { debugPrintError(err) }()

	err = http.ListenAndServeTLS(addr, certFile, keyFile, engine)
	return
}

// RunUnix将路由器连接到http.Server并开始监听和提供HTTP请求
//通过指定的unix套接字（即一个文件）。
//注意：除非发生错误，否则此方法将无限期地阻止调用goroutine。
func (engine *Engine) RunUnix(file string) (err error) {
	debugPrint("Listening and serving HTTP on unix:/%s", file)
	defer func() { debugPrintError(err) }()

	os.Remove(file)
	listener, err := net.Listen("unix", file)
	if err != nil {
		return
	}
	defer listener.Close()
	err = http.Serve(listener, engine)
	return
}

// ServeHTTP符合http.Handler接口。
func (engine *Engine) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	c := engine.pool.Get().(*Context)
	c.writermem.reset(w)
	c.Request = req
	c.reset()

	engine.handleHTTPRequest(c)

	engine.pool.Put(c)
}

// HandleContext重新输入已被重写的上下文。
//这可以通过将c.Request.Path设置为您的新目标来完成。
//免责声明：你可以通过这个循环让自己死亡，明智地使用。
func (engine *Engine) HandleContext(c *Context) {
	c.reset()
	engine.handleHTTPRequest(c)
	engine.pool.Put(c)
}

func (engine *Engine) handleHTTPRequest(c *Context) {
	httpMethod := c.Request.Method
	path := c.Request.URL.Path
	unescape := false
	if engine.UseRawPath && len(c.Request.URL.RawPath) > 0 {
		path = c.Request.URL.RawPath
		unescape = engine.UnescapePathValues
	}

	// Find root of the tree for the given HTTP method
	t := engine.trees
	for i, tl := 0, len(t); i < tl; i++ {
		if t[i].method == httpMethod {
			root := t[i].root
			// Find route in tree
			handlers, params, tsr := root.getValue(path, c.Params, unescape)
			if handlers != nil {
				c.handlers = handlers
				c.Params = params
				c.Next()
				c.writermem.WriteHeaderNow()
				return
			}
			if httpMethod != "CONNECT" && path != "/" {
				if tsr && engine.RedirectTrailingSlash {
					redirectTrailingSlash(c)
					return
				}
				if engine.RedirectFixedPath && redirectFixedPath(c, root, engine.RedirectFixedPath) {
					return
				}
			}
			break
		}
	}

	if engine.HandleMethodNotAllowed {
		for _, tree := range engine.trees {
			if tree.method != httpMethod {
				if handlers, _, _ := tree.root.getValue(path, nil, unescape); handlers != nil {
					c.handlers = engine.allNoMethod
					serveError(c, 405, default405Body)
					return
				}
			}
		}
	}
	c.handlers = engine.allNoRoute
	serveError(c, 404, default404Body)
}

var mimePlain = []string{MIMEPlain}

func serveError(c *Context, code int, defaultMessage []byte) {
	c.writermem.status = code
	c.Next()
	if !c.writermem.Written() {
		if c.writermem.Status() == code {
			c.writermem.Header()["Content-Type"] = mimePlain
			c.Writer.Write(defaultMessage)
		} else {
			c.writermem.WriteHeaderNow()
		}
	}
}

func redirectTrailingSlash(c *Context) {
	req := c.Request
	path := req.URL.Path
	code := 301 // Permanent redirect, request with GET method
	if req.Method != "GET" {
		code = 307
	}

	if length := len(path); length > 1 && path[length-1] == '/' {
		req.URL.Path = path[:length-1]
	} else {
		req.URL.Path = path + "/"
	}
	debugPrint("redirecting request %d: %s --> %s", code, path, req.URL.String())
	http.Redirect(c.Writer, req, req.URL.String(), code)
	c.writermem.WriteHeaderNow()
}

func redirectFixedPath(c *Context, root *node, trailingSlash bool) bool {
	req := c.Request
	path := req.URL.Path

	fixedPath, found := root.findCaseInsensitivePath(
		cleanPath(path),
		trailingSlash,
	)
	if found {
		code := 301 // Permanent redirect, request with GET method
		if req.Method != "GET" {
			code = 307
		}
		req.URL.Path = string(fixedPath)
		debugPrint("redirecting request %d: %s --> %s", code, path, req.URL.String())
		http.Redirect(c.Writer, req, req.URL.String(), code)
		c.writermem.WriteHeaderNow()
		return true
	}
	return false
}
