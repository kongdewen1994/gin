// Copyright 2014 Manu Martinez-Almeida.  All rights reserved.
// Use of this source code is governed by a MIT style
// license that can be found in the LICENSE file.

package gin

import (
	"errors"
	"io"
	"io/ioutil"
	"math"
	"mime/multipart"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/gin-contrib/sse"
	"github.com/gin-gonic/gin/binding"
	"github.com/gin-gonic/gin/render"
)

//最常见数据格式的内容类型MIME。
const (
	MIMEJSON              = binding.MIMEJSON
	MIMEHTML              = binding.MIMEHTML
	MIMEXML               = binding.MIMEXML
	MIMEXML2              = binding.MIMEXML2
	MIMEPlain             = binding.MIMEPlain
	MIMEPOSTForm          = binding.MIMEPOSTForm
	MIMEMultipartPOSTForm = binding.MIMEMultipartPOSTForm
)

const abortIndex int8 = math.MaxInt8 / 2

//上下文是杜松子酒最重要的部分。它允许我们在中间件之间传递变量，
//管理流，验证请求的JSON并呈现JSON响应。
type Context struct {
	writermem responseWriter
	Request   *http.Request
	Writer    ResponseWriter

	Params   Params
	handlers HandlersChain
	index    int8

	engine *Engine

	// Keys是专门用于每个请求上下文的键/值对。
	Keys map[string]interface{}

	//错误是附加到所有使用此上下文的处理程序/中间件的错误列表。
	Errors errorMsgs

	// Accepted定义了用于内容协商的手动接受格式列表。
	Accepted []string
}

/************************************/
/********** CONTEXT CREATION ********/
/************************************/

func (c *Context) reset() {
	c.Writer = &c.writermem
	c.Params = c.Params[0:0]
	c.handlers = nil
	c.index = -1
	c.Keys = nil
	c.Errors = c.Errors[0:0]
	c.Accepted = nil
}

//复制返回当前上下文的副本，可以在请求范围外安全地使用它。
//必须在上下文必须传递给goroutine时使用。
func (c *Context) Copy() *Context {
	var cp = *c
	cp.writermem.ResponseWriter = nil
	cp.Writer = &cp.writermem
	cp.index = abortIndex
	cp.handlers = nil
	return &cp
}

// HandlerName返回主处理程序的名称。例如，如果处理程序是“handleGetUsers（）”，
//这个函数将返回“main.handleGetUsers”。
func (c *Context) HandlerName() string {
	return nameOfFunction(c.handlers.Last())
}

// Handler返回主处理程序。
func (c *Context) Handler() HandlerFunc {
	return c.handlers.Last()
}

/************************************/
/*********** FLOW CONTROL ***********/
/************************************/

//下一步只能在中间件内部使用。
//它执行调用处理程序内链中的挂起处理程序。
//请参阅GitHub中的示例。
func (c *Context) Next() {
	c.index++
	for s := int8(len(c.handlers)); c.index < s; c.index++ {
		c.handlers[c.index](c)
	}
}

//如果当前上下文被中止，IsAborted返回true。
func (c *Context) IsAborted() bool {
	return c.index >= abortIndex
}

//中止阻止挂起的处理程序被调用。请注意，这不会阻止当前处理程序。
//假设您有一个授权中间件来验证当前的请求是否被授权。
//如果授权失败（例如：密码不匹配），请调用Abort来确保剩余的处理程序
//不会调用此请求。
func (c *Context) Abort() {
	c.index = abortIndex
}

// AbortWithStatus调用Abort（）并用指定的状态码写入标题。
//例如，验证请求失败的尝试可以使用：context.AbortWithStatus（401）。
func (c *Context) AbortWithStatus(code int) {
	c.Status(code)
	c.Writer.WriteHeaderNow()
	c.Abort()
}

// AbortWithStatusJSON在内部调用`Abort（）`和`JSON`。
//这个方法停止链，写入状态码并返回一个JSON体。
//它也将Content-Type设置为“application / json”。
func (c *Context) AbortWithStatusJSON(code int, jsonObj interface{}) {
	c.Abort()
	c.JSON(code, jsonObj)
}

// AbortWithError在内部调用`AbortWithStatus（）`和`Error（）`。
//此方法停止链，写入状态码并将指定的错误推送到`c.Errors`。
//有关更多详细信息，请参阅Context.Error（）。
func (c *Context) AbortWithError(code int, err error) *Error {
	c.AbortWithStatus(code)
	return c.Error(err)
}

/************************************/
/********* ERROR MANAGEMENT *********/
/************************************/

//错误将错误附加到当前上下文中。错误被推送到错误列表。
//对请求解析期间发生的每个错误调用Error是一个好主意。
//中间件可用于收集所有错误并将它们一起推送到数据库，
//打印日志，或将其附加到HTTP响应中。
//如果err为零，错误会惊慌。
func (c *Context) Error(err error) *Error {
	if err == nil {
		panic("err is nil")
	}
	var parsedError *Error
	switch err.(type) {
	case *Error:
		parsedError = err.(*Error)
	default:
		parsedError = &Error{
			Err:  err,
			Type: ErrorTypePrivate,
		}
	}
	c.Errors = append(c.Errors, parsedError)
	return parsedError
}

/************************************/
/******** METADATA MANAGEMENT********/
/************************************/

// Set用于专门为此上下文存储新的键/值对。
//它也懒惰初始化c.Keys，如果它以前没有使用。
func (c *Context) Set(key string, value interface{}) {
	if c.Keys == nil {
		c.Keys = make(map[string]interface{})
	}
	c.Keys[key] = value
}

// Get返回给定键的值，即：（value，true）。
//如果该值不存在，则返回（nil，false）
func (c *Context) Get(key string) (value interface{}, exists bool) {
	value, exists = c.Keys[key]
	return
}

// MustGet返回给定键的值（如果存在），否则它会出现混乱。
func (c *Context) MustGet(key string) interface{} {
	if value, exists := c.Get(key); exists {
		return value
	}
	panic("Key \"" + key + "\" does not exist")
}

// GetString以字符串形式返回与键关联的值。
func (c *Context) GetString(key string) (s string) {
	if val, ok := c.Get(key); ok && val != nil {
		s, _ = val.(string)
	}
	return
}

// GetBool返回与该键相关的值作为布尔值。
func (c *Context) GetBool(key string) (b bool) {
	if val, ok := c.Get(key); ok && val != nil {
		b, _ = val.(bool)
	}
	return
}

// GetInt以整数形式返回与键关联的值。
func (c *Context) GetInt(key string) (i int) {
	if val, ok := c.Get(key); ok && val != nil {
		i, _ = val.(int)
	}
	return
}

// GetInt64以整数形式返回与键关联的值。
func (c *Context) GetInt64(key string) (i64 int64) {
	if val, ok := c.Get(key); ok && val != nil {
		i64, _ = val.(int64)
	}
	return
}

// GetFloat64以float64的形式返回与键关联的值。
func (c *Context) GetFloat64(key string) (f64 float64) {
	if val, ok := c.Get(key); ok && val != nil {
		f64, _ = val.(float64)
	}
	return
}

// GetTime返回与键相关的值作为时间。
func (c *Context) GetTime(key string) (t time.Time) {
	if val, ok := c.Get(key); ok && val != nil {
		t, _ = val.(time.Time)
	}
	return
}

// GetDuration返回与该键关联的值作为持续时间。
func (c *Context) GetDuration(key string) (d time.Duration) {
	if val, ok := c.Get(key); ok && val != nil {
		d, _ = val.(time.Duration)
	}
	return
}
// GetStringSlice返回与键相关的值作为一段字符串。
func (c *Context) GetStringSlice(key string) (ss []string) {
	if val, ok := c.Get(key); ok && val != nil {
		ss, _ = val.([]string)
	}
	return
}

// GetStringMap返回与键相关的值作为接口映射。
func (c *Context) GetStringMap(key string) (sm map[string]interface{}) {
	if val, ok := c.Get(key); ok && val != nil {
		sm, _ = val.(map[string]interface{})
	}
	return
}

// GetStringMapString返回与键相关的值作为字符串的映射。
func (c *Context) GetStringMapString(key string) (sms map[string]string) {
	if val, ok := c.Get(key); ok && val != nil {
		sms, _ = val.(map[string]string)
	}
	return
}

// GetStringMapStringSlice将与键关联的值作为映射返回到一段字符串。
func (c *Context) GetStringMapStringSlice(key string) (smss map[string][]string) {
	if val, ok := c.Get(key); ok && val != nil {
		smss, _ = val.(map[string][]string)
	}
	return
}

/************************************/
/************ INPUT DATA ************/
/************************************/

// Param返回URL参数的值。
//这是c.Params.ByName（key）的快捷方式
//      router.GET（“/ user /：id”，func（c * gin.Context）{
//          //对/ user / john的GET请求
//          id：= c.Param（“id”）// id ==“john”
//      }）
func (c *Context) Param(key string) string {
	return c.Params.ByName(key)
}

//查询返回带键控的url查询值（如果存在）
//否则返回一个空字符串`（“”）`。
//这是`c.Request.URL.Query（）。Get（key）`的快捷方式
//      GET / path？id = 1234＆name = Manu＆value =
//  	   c.Query（“id”）==“1234”
//  	   c.Query（“name”）==“Manu”
//  	   c.Query（“value”）==“”
//  	   c.Query（“wtf”）==“”
func (c *Context) Query(key string) string {
	value, _ := c.GetQuery(key)
	return value
}

// DefaultQuery返回带键值的url查询值（如果存在的话）
//否则返回指定的defaultValue字符串。
//请参阅：Query（）和GetQuery（）以获取更多信息。
//      GET /？name = Manu＆lastname =
//      c.DefaultQuery（“name”，“unknown”）==“Manu”
//      c.DefaultQuery（“id”，“none”）==“无”
//      c.DefaultQuery（“lastname”，“none”）==“”
func (c *Context) DefaultQuery(key, defaultValue string) string {
	if value, ok := c.GetQuery(key); ok {
		return value
	}
	return defaultValue
}

// GetQuery就像Query（）一样，它返回键控的url查询值
//如果它存在`（value，true）`（即使该值为空字符串），
//否则返回`（“”，false）`。
//这是`c.Request.URL.Query（）。Get（key）`的快捷方式
//      GET /？name = Manu＆lastname =
//      （“Manu”，true）== c.GetQuery（“name”）
//      （“”，false）== c.GetQuery（“id”）
//      （“”，true）== c.GetQuery（“lastname”）
func (c *Context) GetQuery(key string) (string, bool) {
	if values, ok := c.GetQueryArray(key); ok {
		return values[0], ok
	}
	return "", false
}

// QueryArray为给定的查询键返回一段字符串。
//切片的长度取决于给定键的参数数量。
func (c *Context) QueryArray(key string) []string {
	values, _ := c.GetQueryArray(key)
	return values
}

// GetQueryArray返回给定查询键的字符串片段，加上
//布尔值是否至少有一个值存在给定的键。
func (c *Context) GetQueryArray(key string) ([]string, bool) {
	if values, ok := c.Request.URL.Query()[key]; ok && len(values) > 0 {
		return values, true
	}
	return []string{}, false
}

// PostForm从POST urlencoded表单或多部分表单返回指定的键
//当它存在时，否则它返回一个空字符串`（“”）``。
func (c *Context) PostForm(key string) string {
	value, _ := c.GetPostForm(key)
	return value
}

// DefaultPostForm从POST urlencoded表单或多部分表单返回指定的键
//当它存在时，否则返回指定的defaultValue字符串。
//请参阅：PostForm（）和GetPostForm（）以获取更多信息。
func (c *Context) DefaultPostForm(key, defaultValue string) string {
	if value, ok := c.GetPostForm(key); ok {
		return value
	}
	return defaultValue
}

// GetPostForm就像PostForm（key）。它从urlencoded POST返回指定的密钥
//存在时的形式或多部分形式`（value，true）`（即使值为空字符串），
//否则返回（“”，false）。
//例如，在更新用户电子邮件的PATCH请求期间：
//      email=mail@example.com  - >（“mail@example.com”，true）：= GetPostForm（“email”）//将电子邮件设置为“mail@example.com”
//  	   email =  - >（“”，true）：= GetPostForm（“email”）//将电子邮件设置为“”
//                              - >（“”，false）：= GetPostForm（“email”）//对电子邮件无所作为
func (c *Context) GetPostForm(key string) (string, bool) {
	if values, ok := c.GetPostFormArray(key); ok {
		return values[0], ok
	}
	return "", false
}

// PostFormArray为给定的表单键返回一段字符串。
//切片的长度取决于给定键的参数数量。
func (c *Context) PostFormArray(key string) []string {
	values, _ := c.GetPostFormArray(key)
	return values
}

// GetPostFormArray返回给定表单键的字符串片段，加上
//布尔值是否至少有一个值存在给定的键。
func (c *Context) GetPostFormArray(key string) ([]string, bool) {
	req := c.Request
	req.ParseForm()
	req.ParseMultipartForm(c.engine.MaxMultipartMemory)
	if values := req.PostForm[key]; len(values) > 0 {
		return values, true
	}
	if req.MultipartForm != nil && req.MultipartForm.File != nil {
		if values := req.MultipartForm.Value[key]; len(values) > 0 {
			return values, true
		}
	}
	return []string{}, false
}

// FormFile返回提供的表单键的第一个文件。
func (c *Context) FormFile(name string) (*multipart.FileHeader, error) {
	_, fh, err := c.Request.FormFile(name)
	return fh, err
}

// MultipartForm是解析的多部分表单，包括文件上传。
func (c *Context) MultipartForm() (*multipart.Form, error) {
	err := c.Request.ParseMultipartForm(c.engine.MaxMultipartMemory)
	return c.Request.MultipartForm, err
}

// SaveUploadedFile将表单文件上传到特定的dst。
func (c *Context) SaveUploadedFile(file *multipart.FileHeader, dst string) error {
	src, err := file.Open()
	if err != nil {
		return err
	}
	defer src.Close()

	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer out.Close()

	io.Copy(out, src)
	return nil
}

//绑定检查Content-Type自动选择绑定引擎，
//根据“Content-Type”标题使用不同的绑定：
//      “application / json” - > JSON绑定
//      “application / xml” - > XML绑定
//否则 - >返回错误。
//如果Content-Type ==“application / json”使用JSON或XML作为JSON输入，它会将请求的主体解析为JSON。
//它将json有效载荷解码为指定为指针的结构体。
//如果输入无效，它会写入400错误并在响应中设置Content-Type标头“text / plain”。
func (c *Context) Bind(obj interface{}) error {
	b := binding.Default(c.Request.Method, c.ContentType())
	return c.MustBindWith(obj, b)
}

// BindJSON是c.MustBindWith（obj，binding.JSON）的快捷方式。
func (c *Context) BindJSON(obj interface{}) error {
	return c.MustBindWith(obj, binding.JSON)
}

// BindQuery是c.MustBindWith（obj，binding.Query）的快捷方式。
func (c *Context) BindQuery(obj interface{}) error {
	return c.MustBindWith(obj, binding.Query)
}

// MustBindWith使用指定的绑定引擎绑定传递的结构指针。
//如果有错误发生，它将使用HTTP 400中止请求。
//查看绑定包。
func (c *Context) MustBindWith(obj interface{}, b binding.Binding) (err error) {
	if err = c.ShouldBindWith(obj, b); err != nil {
		c.AbortWithError(400, err).SetType(ErrorTypeBind)
	}

	return
}

// ShouldBind检查Content-Type自动选择绑定引擎，
//根据“Content-Type”标题使用不同的绑定：
//      “application / json” - > JSON绑定
//      “application / xml” - > XML绑定
//否则 - >返回错误
//如果Content-Type ==“application / json”使用JSON或XML作为JSON输入，它会将请求的主体解析为JSON。
//它将json有效载荷解码为指定为指针的结构体。
//和c.Bind（）一样，但是这个方法不会将响应状态码设置为400，并且如果json无效则中止。
func (c *Context) ShouldBind(obj interface{}) error {
	b := binding.Default(c.Request.Method, c.ContentType())
	return c.ShouldBindWith(obj, b)
}

// ShouldBindJSON是c.ShouldBindWith（obj，binding.JSON）的快捷方式。
func (c *Context) ShouldBindJSON(obj interface{}) error {
	return c.ShouldBindWith(obj, binding.JSON)
}

// ShouldBindQuery是c.ShouldBindWith（obj，binding.Query）的快捷方式。
func (c *Context) ShouldBindQuery(obj interface{}) error {
	return c.ShouldBindWith(obj, binding.Query)
}

// ShouldBindWith使用指定的绑定引擎绑定传递的结构指针。
//查看绑定包。
func (c *Context) ShouldBindWith(obj interface{}, b binding.Binding) error {
	return b.Bind(c.Request, obj)
}

// ClientIP实现尽力而为的算法来返回真实的客户端IP，它解析
// X-Real-IP和X-Forwarded-For为了与反向代理如us：nginx或haproxy正常工作。
//使用X-Forwarded-For X-Real-Ip作为nginx使用带有代理IP的X-Real-Ip。
func (c *Context) ClientIP() string {
	if c.engine.ForwardedByClientIP {
		clientIP := c.requestHeader("X-Forwarded-For")
		if index := strings.IndexByte(clientIP, ','); index >= 0 {
			clientIP = clientIP[0:index]
		}
		clientIP = strings.TrimSpace(clientIP)
		if clientIP != "" {
			return clientIP
		}
		clientIP = strings.TrimSpace(c.requestHeader("X-Real-Ip"))
		if clientIP != "" {
			return clientIP
		}
	}

	if c.engine.AppEngine {
		if addr := c.requestHeader("X-Appengine-Remote-Addr"); addr != "" {
			return addr
		}
	}

	if ip, _, err := net.SplitHostPort(strings.TrimSpace(c.Request.RemoteAddr)); err == nil {
		return ip
	}

	return ""
}

// ContentType返回请求的Content-Type头。
func (c *Context) ContentType() string {
	return filterFlags(c.requestHeader("Content-Type"))
}

//如果请求标头指示websocket，则IsWebsocket返回true
//握手由客户端发起。
func (c *Context) IsWebsocket() bool {
	if strings.Contains(strings.ToLower(c.requestHeader("Connection")), "upgrade") &&
		strings.ToLower(c.requestHeader("Upgrade")) == "websocket" {
		return true
	}
	return false
}

func (c *Context) requestHeader(key string) string {
	return c.Request.Header.Get(key)
}

/************************************/
/******** RESPONSE RENDERING ********/
/************************************/

// bodyAllowedForStatus是http.bodyAllowedForStatus非导出函数的副本。
func bodyAllowedForStatus(status int) bool {
	switch {
	case status >= 100 && status <= 199:
		return false
	case status == 204:
		return false
	case status == 304:
		return false
	}
	return true
}

//状态设置HTTP响应代码。
func (c *Context) Status(code int) {
	c.writermem.WriteHeader(code)
}

// Header是c.Writer.Header（）的智能快捷键。Set（key，value）。
//它在响应中写入一个头文件。
//如果value ==“”，这个方法删除头部`c.Writer.Header（）。Del（key）`
func (c *Context) Header(key, value string) {
	if value == "" {
		c.Writer.Header().Del(key)
	} else {
		c.Writer.Header().Set(key, value)
	}
}

// GetHeader从请求头返回值。
func (c *Context) GetHeader(key string) string {
	return c.requestHeader(key)
}

// GetRawData返回流数据。
func (c *Context) GetRawData() ([]byte, error) {
	return ioutil.ReadAll(c.Request.Body)
}

// SetCookie将一个Set-Cookie头添加到ResponseWriter的头文件中。
//提供的cookie必须具有有效的名称。无效的Cookie可能是
//默默地放下。
func (c *Context) SetCookie(name, value string, maxAge int, path, domain string, secure, httpOnly bool) {
	if path == "" {
		path = "/"
	}
	http.SetCookie(c.Writer, &http.Cookie{
		Name:     name,
		Value:    url.QueryEscape(value),
		MaxAge:   maxAge,
		Path:     path,
		Domain:   domain,
		Secure:   secure,
		HttpOnly: httpOnly,
	})
}

// Cookie返回请求中提供的命名cookie
// ErrNoCookie，如果没有找到。并返回指定的cookie未转义。
//如果多个cookie匹配给定名称，则只会有一个cookie
//被退回。
func (c *Context) Cookie(name string) (string, error) {
	cookie, err := c.Request.Cookie(name)
	if err != nil {
		return "", err
	}
	val, _ := url.QueryUnescape(cookie.Value)
	return val, nil
}

func (c *Context) Render(code int, r render.Render) {
	c.Status(code)

	if !bodyAllowedForStatus(code) {
		r.WriteContentType(c.Writer)
		c.Writer.WriteHeaderNow()
		return
	}

	if err := r.Render(c.Writer); err != nil {
		panic(err)
	}
}

// HTML呈现由其文件名指定的HTTP模板。
//它还更新HTTP代码并将Content-Type设置为“text / html”。
//请参阅http://golang.org/doc/articles/wiki/
func (c *Context) HTML(code int, name string, obj interface{}) {
	instance := c.engine.HTMLRender.Instance(name, obj)
	c.Render(code, instance)
}

// IndentedJSON将给定的结构体序列化为漂亮的JSON（缩进+结束符）到响应主体中。
//它也将Content-Type设置为“application / json”。
//警告：我们建议使用它仅用于开发目的，因为打印漂亮的JSON是
//更多的CPU和带宽消耗。改为使用Context.JSON（）。
func (c *Context) IndentedJSON(code int, obj interface{}) {
	c.Render(code, render.IndentedJSON{Data: obj})
}

// SecureJSON将给定的结构体作为安全JSON序列化到响应主体中。
//如果给定的结构是数组值，则默认prepends“while（1），”给响应主体。
//它也将Content-Type设置为“application / json”。
func (c *Context) SecureJSON(code int, obj interface{}) {
	c.Render(code, render.SecureJSON{Prefix: c.engine.secureJsonPrefix, Data: obj})
}

// JSON将给定的结构体作为JSON序列化到响应体中。
//它也将Content-Type设置为“application / json”。
func (c *Context) JSON(code int, obj interface{}) {
	c.Render(code, render.JSON{Data: obj})
}

// XML将给定的结构体作为XML序列化到响应主体中。
//它也将Content-Type设置为“application / xml”。
func (c *Context) XML(code int, obj interface{}) {
	c.Render(code, render.XML{Data: obj})
}

// YAML将给定的结构体作为YAML序列化到响应体中。
func (c *Context) YAML(code int, obj interface{}) {
	c.Render(code, render.YAML{Data: obj})
}

// String将给定的字符串写入响应主体。
func (c *Context) String(code int, format string, values ...interface{}) {
	c.Render(code, render.String{Format: format, Data: values})
}

//重定向会将HTTP重定向返回到特定位置。
func (c *Context) Redirect(code int, location string) {
	c.Render(-1, render.Redirect{
		Code:     code,
		Location: location,
		Request:  c.Request,
	})
}

//数据将一些数据写入正文流并更新HTTP代码。
func (c *Context) Data(code int, contentType string, data []byte) {
	c.Render(code, render.Data{
		ContentType: contentType,
		Data:        data,
	})
}

// File以有效的方式将指定的文件写入正文流。
func (c *Context) File(filepath string) {
	http.ServeFile(c.Writer, c.Request, filepath)
}

// SSEvent将一个Server-Sent事件写入主体流。
func (c *Context) SSEvent(name string, message interface{}) {
	c.Render(-1, sse.Event{
		Event: name,
		Data:  message,
	})
}

func (c *Context) Stream(step func(w io.Writer) bool) {
	w := c.Writer
	clientGone := w.CloseNotify()
	for {
		select {
		case <-clientGone:
			return
		default:
			keepOpen := step(w)
			w.Flush()
			if !keepOpen {
				return
			}
		}
	}
}

/************************************/
/******** CONTENT NEGOTIATION *******/
/************************************/

type Negotiate struct {
	Offered  []string
	HTMLName string
	HTMLData interface{}
	JSONData interface{}
	XMLData  interface{}
	Data     interface{}
}

func (c *Context) Negotiate(code int, config Negotiate) {
	switch c.NegotiateFormat(config.Offered...) {
	case binding.MIMEJSON:
		data := chooseData(config.JSONData, config.Data)
		c.JSON(code, data)

	case binding.MIMEHTML:
		data := chooseData(config.HTMLData, config.Data)
		c.HTML(code, config.HTMLName, data)

	case binding.MIMEXML:
		data := chooseData(config.XMLData, config.Data)
		c.XML(code, data)

	default:
		c.AbortWithError(http.StatusNotAcceptable, errors.New("the accepted formats are not offered by the server"))
	}
}

func (c *Context) NegotiateFormat(offered ...string) string {
	assert1(len(offered) > 0, "you must provide at least one offer")

	if c.Accepted == nil {
		c.Accepted = parseAccept(c.requestHeader("Accept"))
	}
	if len(c.Accepted) == 0 {
		return offered[0]
	}
	for _, accepted := range c.Accepted {
		for _, offert := range offered {
			if accepted == offert {
				return offert
			}
		}
	}
	return ""
}

func (c *Context) SetAccepted(formats ...string) {
	c.Accepted = formats
}

/************************************/
/***** GOLANG.ORG/X/NET/CONTEXT *****/
/************************************/

func (c *Context) Deadline() (deadline time.Time, ok bool) {
	return
}

func (c *Context) Done() <-chan struct{} {
	return nil
}

func (c *Context) Err() error {
	return nil
}

func (c *Context) Value(key interface{}) interface{} {
	if key == 0 {
		return c.Request
	}
	if keyAsString, ok := key.(string); ok {
		val, _ := c.Get(keyAsString)
		return val
	}
	return nil
}
