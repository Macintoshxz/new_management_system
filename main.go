package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"management-system/config"
	"management-system/logic"
	"management-system/middleware"
	"management-system/pkg/utils"
	"management-system/response"
	"management-system/vo"
	"net/http"
	"net/smtp"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/gin-contrib/sessions"
	"github.com/gin-contrib/sessions/cookie"
	"github.com/gin-gonic/gin"
	"github.com/jordan-wright/email"
	"github.com/qiniu/qmgo"
	"github.com/qiniu/qmgo/field"
	"github.com/qiniu/qmgo/options"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	mOption "go.mongodb.org/mongo-driver/mongo/options"
)

var cf *config.Config
var mongoCliOptions *options.ClientOptions

func isTargetDatePlusDays(targetTime time.Time, days int) bool {
	// 获取今天的时间
	now := time.Now().Truncate(24 * time.Hour)

	// 计算目标时间加上指定天数后的时间
	plusDays := targetTime.Add(time.Duration(days) * 24 * time.Hour).Truncate(24 * time.Hour)

	// 判断是否是今天
	return plusDays.Equal(now)
}

func MailSendCode(emailstr, msg string) (err error) {

	e := email.NewEmail()
	e.From = "BAM <13609062201@163.com>"
	// xingyi1228@gmail.com
	e.To = []string{"xingyi1228@gmail.com", emailstr}
	e.Subject = "[Revisit PM] " + msg

	str := "This a reminder email: You marked 'pass & revisit' for [" + msg + "] in the pipeline database. It's now time to revisit it."
	e.HTML = []byte(str)
	err = e.SendWithTLS("smtp.163.com:465",
		// 注意这里的密码不是邮箱登录密码, 是开启 smtp 服务后获取的一串验证码
		smtp.PlainAuth("", "13609062201@163.com", "DSKSFGBDPPVVOKRV", "smtp.163.com"),
		// 指定跳过安全验证 ，
		&tls.Config{InsecureSkipVerify: true, ServerName: "smtp.163.com"})
	if err != nil {
		log.Println("Failed to send mail", err)
		panic(err)
	}
	return
}

func main() {

	// 初始化配置文件
	config.Init()
	cf = config.GetCofnig()
	fmt.Printf("cf.Mongodb: %v\n", cf.Mongodb)

	// read pemfile data
	pemData, err := ioutil.ReadFile("./global-bundle.pem")
	if err != nil {
		log.Panic(err)
	}

	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(pemData) {
		log.Panic(errors.New("failed to parse root certificate"))
	}

	// set tls config
	tlsConfig := &tls.Config{
		RootCAs:            roots,
		InsecureSkipVerify: true,
	}
	mongoCliOptions = &options.ClientOptions{
		ClientOptions: mOption.Client(),
	}
	fmt.Printf("mongoCliOptions: %v\n", mongoCliOptions)
	mongoCliOptions.SetTLSConfig(tlsConfig)

	logic.StartTimer(func() {

		c := context.Background()
		cli, err := qmgo.Open(c, &qmgo.Config{Uri: cf.Mongodb.URL, Database: cf.Mongodb.DataBase, Coll: "info",
			Auth: &qmgo.Credential{
				AuthMechanism: cf.Mongodb.AuthMechanism,
				Username:      cf.Mongodb.UserName,
				Password:      cf.Mongodb.Password,
				PasswordSet:   cf.Mongodb.PasswordSet,
			}}, *mongoCliOptions)
		defer func() {
			if err = cli.Close(c); err != nil {
				panic(err)
			}
		}()
		if err != nil {
			utils.CheckError(err, "mongodb connection exception")
			return
		}
		// 查询条件
		filter := bson.M{}
		var infos []logic.BaseInfo
		// 查询数据
		err = cli.Find(c, filter).Sort("-updateAt").All(&infos)
		utils.CheckError(err, "mongodb connection exception")

		for _, v := range infos {
			result, err := strconv.Atoi(v.HowRevisit)
			if err == nil {
				if isTargetDatePlusDays(v.UpdateAt, result) {
					go func(baseinfo logic.BaseInfo) {
						MailSendCode(baseinfo.CreateBy, baseinfo.Manager)
					}(v)
				}
			}

		}

	})

	// 初始化路由组
	var htmlByte = map[string][]byte{
		"./static/pages/info.html":     nil,
		"./static/pages/login.html":    nil,
		"./static/pages/register.html": nil,
	}

	// 读取整个文件内容
	for k, _ := range htmlByte {
		content, err := ioutil.ReadFile(k)
		if err != nil {
			fmt.Printf("err.Error(): %v\n", err.Error())
			return
		}

		htmlByte[k] = content
	}
	router := gin.Default()
	// 使用 Cookie 存储 session
	store := cookie.NewStore([]byte("secret"))
	router.Use(sessions.Sessions("mysession", store))
	// 权限校验
	router.Use(middleware.AuthHandler())
	// 统一异常处理
	router.Use(middleware.ErrorHandler())
	// 静态资源
	router.Static("/css", "./static/css")
	router.Static("/js", "./static/js")
	router.Static("/image", "./static/image")
	router.Static("/plugins", "./static/plugins")
	router.Static("/files", "./files/")
	// router.LoadHTMLGlob("static/pages/*")
	router.GET("/", func(c *gin.Context) {
		c.Data(http.StatusOK, "text/html; charset=utf-8", htmlByte["./static/pages/info.html"])
	})
	router.GET("/login", func(c *gin.Context) {
		c.Data(http.StatusOK, "text/html; charset=utf-8", htmlByte["./static/pages/login.html"])
	})
	router.GET("/register", func(c *gin.Context) {
		c.Data(http.StatusOK, "text/html; charset=utf-8", htmlByte["./static/pages/register.html"])
	})
	router.GET("/info", func(c *gin.Context) {
		c.Data(http.StatusOK, "text/html; charset=utf-8", htmlByte["./static/pages/info.html"])
	})

	// 简单的路由组: v1
	v1 := router.Group("/v1")

	v1.POST("/upload", upload)

	user := v1.Group("/user")
	user.POST("/login", login)
	user.POST("/register", register)
	user.GET("/logout", logout)

	infoGroup := v1.Group("/info")
	infoGroup.POST("/page", queryPage)
	infoGroup.POST("/add", addInfo)
	infoGroup.POST("/update", editInfo)
	infoGroup.POST("/delete", deleteInfo)
	infoGroup.GET("/:id", getInfo)

	reviewHistoryGourp := v1.Group("/reviewHistory")
	reviewHistoryGourp.POST("/edit", editCommHistory)
	reviewHistoryGourp.POST("/add", addCommHistory)
	reviewHistoryGourp.GET("/list/:id", getCommHistoryByInfoId)
	reviewHistoryGourp.GET("/:id", getHistory)

	endPoint := fmt.Sprintf(":%d", config.GetCofnig().Appserver.AppPort)
	maxHeaderBytes := 1 << 20
	// 自定义配置服务
	server := &http.Server{
		Addr:           endPoint,
		Handler:        router,
		ReadTimeout:    10 * time.Second,
		WriteTimeout:   10 * time.Second,
		MaxHeaderBytes: maxHeaderBytes,
	}
	fmt.Printf("[info] start http server listening %s", endPoint)
	server.ListenAndServe()

}

func upload(c *gin.Context) {
	var (
		app = response.Gin{C: c}
	)
	// 解析表单数据，限制最大文件大小为 8MB
	if err := c.Request.ParseMultipartForm(8 << 20); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// 获取当前日期
	now := time.Now()
	year := now.Format("2006")
	month := now.Format("01")
	day := now.Format("02")

	// 构建上传文件保存路径
	uploadPath := fmt.Sprintf("./files/%s/%s/%s/", year, month, day)
	if err := os.MkdirAll(uploadPath, os.ModePerm); err != nil {
		utils.CheckError(err, "构建保存路径异常")
		return
	}

	// 获取所有上传的文件
	form := c.Request.MultipartForm
	files := form.File["file"]
	var targePath []string
	// 遍历所有文件
	for _, file := range files {
		// 构建文件名，确保文件名不包含特殊字符
		filename := strings.ReplaceAll(file.Filename, " ", "_")
		// 检查文件后缀是否允许上传
		if !isAllowedFileType(filename) {
			app.ResponseErr("Invalid file type", nil)
			return
		}

		// 保存文件到指定路径
		// fileStr := strings.Split(filename, ".")
		// filename = fileStr[0] + strconv.Itoa(time.Now().Local().Second()) + fileStr[1]
		filePath := filepath.Join(uploadPath, filename)
		targePath = append(targePath, filePath)
		err := c.SaveUploadedFile(file, filePath)
		if err != nil {
			utils.CheckError(err, "Save file exception")
			return
		}
	}

	resultPath := strings.Join(targePath, ",")
	app.ResponseSuccess("上传成功", resultPath)
}

func login(c *gin.Context) {
	// 生成令牌
	var (
		app = response.Gin{C: c}
		req = vo.LoginBody{}
	)
	err := c.ShouldBindJSON(&req)
	cli, err := qmgo.Open(c, &qmgo.Config{Uri: cf.Mongodb.URL, Database: cf.Mongodb.DataBase, Coll: "user",
		Auth: &qmgo.Credential{
			AuthMechanism: cf.Mongodb.AuthMechanism,
			Username:      cf.Mongodb.UserName,
			Password:      cf.Mongodb.Password,
			PasswordSet:   cf.Mongodb.PasswordSet,
		},
	})
	defer func() {
		if err = cli.Close(c); err != nil {
			panic(err)
		}
	}()
	userInfo := logic.User{}
	err = cli.Find(c, bson.M{"email": req.Email, "password": req.Password}).One(&userInfo)
	utils.CheckError(err, "login failure")

	if userInfo.Id.IsZero() {
		app.ResponseErr("login failure", nil)
		return
	}

	// 假设登录成功后，将用户信息存入 session
	session := sessions.Default(c)
	session.Set("userID", userInfo.Id.String())
	session.Set("email", userInfo.Email)
	session.Save()

	// 登录成功后重定向到首页
	app.ResponseSuccess("login success", nil)
}

func logout(c *gin.Context) {
	var (
		app = response.Gin{C: c}
	)
	session := sessions.Default(c)
	session.Clear()
	session.Save()
	app.ResponseSuccess("loginOut success", nil)
}

func register(c *gin.Context) {
	var (
		app = response.Gin{C: c}
		req = vo.RegisterBody{}
	)

	err := c.ShouldBindJSON(&req)
	cli, err := qmgo.Open(c, &qmgo.Config{Uri: cf.Mongodb.URL, Database: cf.Mongodb.DataBase, Coll: "user",
		Auth: &qmgo.Credential{
			AuthMechanism: cf.Mongodb.AuthMechanism,
			Username:      cf.Mongodb.UserName,
			Password:      cf.Mongodb.Password,
			PasswordSet:   cf.Mongodb.PasswordSet,
		},
	})

	if err != nil {
		utils.CheckError(err, "mongodb connection exception")
		return
	}
	defer func() {
		if err = cli.Close(c); err != nil {
			panic(err)
		}
	}()
	// one := logic.User{}
	count, err := cli.Find(c, bson.M{"email": req.Email}).Count()
	if err != nil {
		utils.CheckError(err, "mongodb connection exception")
		return
	}

	if count > 0 {
		app.ResponseErr("The email address has been registered", nil)
		return
	}
	// m, err := sysLoginLogic.Login(req.UserName, req.Password, req.Code, "")
	userInfo := &logic.User{
		Email:    req.Email,
		UserName: req.Name,
		Password: req.Password,
	}
	_, err = cli.InsertOne(c, userInfo)
	if err != nil {
		utils.CheckError(err, "fail to register ")
		return
	}

	if err != nil {
		utils.CheckError(err, "mongodb connection exception")
		return
	}

	if userInfo.Id.IsZero() {
		app.ResponseSuccess("fail to register", nil)
		return
	}

	app.ResponseSuccess("register success", nil)
}

func addInfo(c *gin.Context) {

	var (
		app = response.Gin{C: c}
		req = &vo.InfoVo{}
	)

	err := c.ShouldBindJSON(&req)
	utils.CheckError(err, "Parameter exception")

	client, err := qmgo.NewClient(c, &qmgo.Config{Uri: cf.Mongodb.URL,
		Auth: &qmgo.Credential{
			AuthMechanism: cf.Mongodb.AuthMechanism,
			Username:      cf.Mongodb.UserName,
			Password:      cf.Mongodb.Password,
			PasswordSet:   cf.Mongodb.PasswordSet,
		}})
	utils.CheckError(err, "mongodb connection exception")

	defer func() {
		if err = client.Close(c); err != nil {
			panic(err)
		}
	}()

	db := client.Database("management")
	coll := db.Collection("info")
	session := sessions.Default(c)
	email := session.Get("email")
	baseinfo := &logic.BaseInfo{
		Manager:                   req.Manager,
		LabsLeads:                 req.LabsLeads,
		PmCioName:                 req.PmCioName,
		Type:                      req.Type,
		FormerEmployer:            req.FormerEmployer,
		FirmAUM:                   req.FirmAUM,
		Source:                    req.Source,
		AvailableStrategyCapacity: req.AvailableStrategyCapacity,
		LinkedinPage:              req.LinkedinPage,
		EmailContact:              req.EmailContact,
		FilePath:                  req.FilePath,
		CurrentStage:              req.CurrentStage,
		NeedRevisit:               "no",
		HowRevisit:                req.HowRevisit,
		CreateBy:                  email.(string),
		DefaultField: field.DefaultField{
			UpdateAt: req.ReviewDate,
		},
	}
	// 重要：确保事务中的每一个操作，都使用传入的sessCtx参数
	if _, err := coll.InsertOne(c, baseinfo); err != nil {
		utils.CheckError(err, "info insert error")
		return
	}

	err = coll.UpdateOne(c, bson.M{"_id": baseinfo.Id}, bson.M{"$set": bson.M{
		"updateAt": req.ReviewDate,
	}})

	if err != nil {
		utils.CheckError(err, "info insert error")
		return
	}

	coll = db.Collection("commhistory")
	commhistory := &logic.CommHistory{
		BaseInfoId:       baseinfo.Id.Hex(),
		ReviewDate:       req.ReviewDate,
		CurrentStage:     req.CurrentStage,
		Comment:          req.Comment,
		InvestConviction: req.InvestConviction,
		IsRevisit:        req.IsRevisit,
		HowRevisit:       req.HowRevisit,
	}
	if _, err := coll.InsertOne(c, commhistory); err != nil {
		utils.CheckError(err, "history insert error")
		return
	}

	app.ResponseSuccess("save success", nil)
}

func queryPage(c *gin.Context) {
	// 生成令牌
	var (
		app = response.Gin{C: c}
		req = vo.PageRequest{}
	)
	err := c.ShouldBindJSON(&req)
	utils.CheckError(err, "Parameter exception")

	cli, err := qmgo.Open(c, &qmgo.Config{Uri: cf.Mongodb.URL, Database: cf.Mongodb.DataBase, Coll: "info",
		Auth: &qmgo.Credential{
			AuthMechanism: cf.Mongodb.AuthMechanism,
			Username:      cf.Mongodb.UserName,
			Password:      cf.Mongodb.Password,
			PasswordSet:   cf.Mongodb.PasswordSet,
		},
	})

	defer func() {
		if err = cli.Close(c); err != nil {
			panic(err)
		}
	}()
	if err != nil {
		utils.CheckError(err, "mongodb connection exception")
		return
	}
	// 查询条件
	filter := bson.M{}
	if req.Filter["manager"] != "" {
		filter["manager"] = primitive.Regex{
			Pattern: req.Filter["manager"].(string),
			Options: "",
		}
	}
	var infos []logic.BaseInfo
	// 查询数据
	err = cli.Find(c, filter).Sort("-updateAt").
		Skip((req.PageNum - 1) * req.PageSize).Limit(req.PageSize).All(&infos)
	utils.CheckError(err, "mongodb connection exception")

	count, err := cli.Find(c, filter).Count()
	utils.CheckError(err, "mongodb connection exception")

	app.ResponsePage("query success", infos, int(count))

}

func getInfo(c *gin.Context) {
	// 生成令牌
	var (
		app = response.Gin{C: c}
		req = vo.ReqId{}
	)
	err := c.ShouldBindUri(&req)
	utils.CheckError(err, "Parameter exception")

	cli, err := qmgo.Open(c, &qmgo.Config{Uri: cf.Mongodb.URL, Database: cf.Mongodb.DataBase, Coll: "info",
		Auth: &qmgo.Credential{
			AuthMechanism: cf.Mongodb.AuthMechanism,
			Username:      cf.Mongodb.UserName,
			Password:      cf.Mongodb.Password,
			PasswordSet:   cf.Mongodb.PasswordSet,
		},
	})
	defer func() {
		if err = cli.Close(c); err != nil {
			panic(err)
		}
	}()
	if err != nil {
		utils.CheckError(err, "mongodb connection exception")
		return
	}

	id, err := primitive.ObjectIDFromHex(req.Id)
	utils.CheckError(err, "id resolution exception")
	// 查询条件
	filter := bson.M{
		"_id": id,
	}
	// 查询一个文档
	one := logic.BaseInfo{}
	err = cli.Find(c, filter).One(&one)
	utils.CheckError(err, "mongodb connection exception")

	app.ResponseSuccess("Query success", one)
}

func deleteInfo(c *gin.Context) {
	// 生成令牌
	var (
		app = response.Gin{C: c}
		req = vo.ReqIds{}
	)
	err := c.ShouldBindJSON(&req)
	utils.CheckError(err, "Parameter exception")

	client, err := qmgo.NewClient(c, &qmgo.Config{Uri: cf.Mongodb.URL, Auth: &qmgo.Credential{
		AuthMechanism: cf.Mongodb.AuthMechanism,
		Username:      cf.Mongodb.UserName,
		Password:      cf.Mongodb.Password,
		PasswordSet:   cf.Mongodb.PasswordSet,
	}})
	utils.CheckError(err, "mongodb connection exception")

	defer func() {
		if err = client.Close(c); err != nil {
			panic(err)
		}
	}()

	db := client.Database("management")
	coll := db.Collection("info")

	var idsToDelete []primitive.ObjectID
	for i := range req.Ids {
		id, err := primitive.ObjectIDFromHex(req.Ids[i])
		if err != nil {
			app.ResponseErr("id error", nil)
			return
		}
		idsToDelete = append(idsToDelete, id)
	}

	// 构造删除的条件
	filter := bson.M{"_id": bson.M{"$in": idsToDelete}}

	// 删除匹配条件的文档
	DeleteResult, err := coll.RemoveAll(c, filter)
	utils.CheckError(err, "mongodb remove error")

	coll = db.Collection("commhistory")
	// 删除匹配条件的文档
	_, err = coll.RemoveAll(c, filter)
	utils.CheckError(err, "mongodb remove error")

	app.ResponseSuccess("delete success", DeleteResult)
}

func editInfo(c *gin.Context) {
	// 生成令牌
	var (
		app = response.Gin{C: c}
		req = &logic.BaseInfo{}
	)
	err := c.ShouldBindJSON(&req)
	utils.CheckError(err, "Parameter exception")

	coll, err := qmgo.Open(c, &qmgo.Config{Uri: cf.Mongodb.URL, Database: cf.Mongodb.DataBase, Coll: "info",
		Auth: &qmgo.Credential{
			AuthMechanism: cf.Mongodb.AuthMechanism,
			Username:      cf.Mongodb.UserName,
			Password:      cf.Mongodb.Password,
			PasswordSet:   cf.Mongodb.PasswordSet,
		}})
	defer func() {
		if err = coll.Close(c); err != nil {
			panic(err)
		}
	}()

	utils.CheckError(err, "mongodb connection exception")

	// id, err := primitive.ObjectIDFromHex(req.Id.String())
	// utils.CheckError(err, "id resolution exception")

	// 你的更新内容，这里假设你要将 Field 更新为 "UpdatedValue"
	updateContent := bson.M{"$set": bson.M{
		"manager":        req.Manager,
		"labsLeads":      req.LabsLeads,
		"pmCioName":      req.PmCioName,
		"type":           req.Type,
		"formerEmployer": req.FormerEmployer,
		"firmAUM":        req.FirmAUM,
		"source":         req.Source,
		"asCapacity":     req.AvailableStrategyCapacity,
		"linkedinPage":   req.LinkedinPage,
		"emailContact":   req.EmailContact,
		"filePath":       req.FilePath,
	}}

	// 使用 UpdateOne 更新单个文档
	err = coll.UpdateOne(c, bson.M{"_id": req.Id}, updateContent)

	utils.CheckError(err, "")

	app.ResponseSuccess("modify successfully", nil)
}

func editCommHistory(c *gin.Context) {
	// 生成令牌
	var (
		app = response.Gin{C: c}
		req = &logic.CommHistory{}
	)
	err := c.ShouldBindJSON(&req)
	utils.CheckError(err, "Parameter exception")

	client, err := qmgo.NewClient(c, &qmgo.Config{Uri: cf.Mongodb.URL, Auth: &qmgo.Credential{
		AuthMechanism: cf.Mongodb.AuthMechanism,
		Username:      cf.Mongodb.UserName,
		Password:      cf.Mongodb.Password,
		PasswordSet:   cf.Mongodb.PasswordSet,
	}})
	utils.CheckError(err, "mongodb connection exception")

	defer func() {
		if err = client.Close(c); err != nil {
			panic(err)
		}
	}()

	db := client.Database("management")
	coll := db.Collection("commhistory")

	utils.CheckError(err, "mongodb connection exception")

	id, err := primitive.ObjectIDFromHex(req.Id.String())
	utils.CheckError(err, "id resolution exception")

	// 你的更新内容，这里假设你要将 Field 更新为 "UpdatedValue"
	updateContent := bson.M{"$set": bson.M{
		"reviewDate":       req.ReviewDate,
		"comment":          req.Comment,
		"currentStage":     req.CurrentStage,
		"investConviction": req.InvestConviction,
		"isRevisit":        req.IsRevisit,
		"howRevisit":       req.HowRevisit,
	}}

	infoId, err := primitive.ObjectIDFromHex(req.BaseInfoId)
	utils.CheckError(err, "infoid resolution exception")
	// 使用 UpdateOne 更新单个文档
	err = coll.UpdateOne(c, bson.M{"_id": id}, updateContent)
	utils.CheckError(err, "")

	coll = db.Collection("info")
	err = coll.UpdateOne(c, bson.M{"_id": infoId}, bson.M{"$set": bson.M{
		"currentStage": req.CurrentStage,
		"needRevisit":  req.IsRevisit,
	}})

	app.ResponseSuccess("modify successfully", nil)
}

func addCommHistory(c *gin.Context) {
	// 生成令牌
	var (
		app = response.Gin{C: c}
		req = &logic.CommHistory{}
	)
	err := c.ShouldBindJSON(&req)
	utils.CheckError(err, "Parameter exception")

	client, err := qmgo.NewClient(c, &qmgo.Config{Uri: cf.Mongodb.URL, Auth: &qmgo.Credential{
		AuthMechanism: cf.Mongodb.AuthMechanism,
		Username:      cf.Mongodb.UserName,
		Password:      cf.Mongodb.Password,
		PasswordSet:   cf.Mongodb.PasswordSet,
	}})
	utils.CheckError(err, "mongodb connection exception")

	defer func() {
		if err = client.Close(c); err != nil {
			panic(err)
		}
	}()

	db := client.Database("management")
	coll := db.Collection("commhistory")

	utils.CheckError(err, "mongodb connection exception")
	result, err := coll.InsertOne(c, req)
	utils.CheckError(err, "")

	coll = db.Collection("info")
	infoId, err := primitive.ObjectIDFromHex(req.BaseInfoId)
	utils.CheckError(err, "infoid resolution exception")
	err = coll.UpdateOne(c, bson.M{"_id": infoId}, bson.M{"$set": bson.M{
		"currentStage": req.CurrentStage,
		"needRevisit":  req.IsRevisit,
		"updateAt":     req.ReviewDate,
	}})

	app.ResponseSuccess("添加成功", result)
}

func getCommHistoryByInfoId(c *gin.Context) {
	// 生成令牌
	var (
		app = response.Gin{C: c}
		req = &vo.ReqId{}
	)
	err := c.ShouldBindUri(&req)
	utils.CheckError(err, "Parameter exception")

	coll, err := qmgo.Open(c, &qmgo.Config{Uri: cf.Mongodb.URL, Database: cf.Mongodb.DataBase, Coll: "commhistory", Auth: &qmgo.Credential{
		AuthMechanism: cf.Mongodb.AuthMechanism,
		Username:      cf.Mongodb.UserName,
		Password:      cf.Mongodb.Password,
		PasswordSet:   cf.Mongodb.PasswordSet,
	}})
	defer func() {
		if err = coll.Close(c); err != nil {
			panic(err)
		}
	}()
	// 查询条件
	filter := bson.M{
		"baseInfoId": req.Id,
	}
	// 查询所有数据
	var items []logic.CommHistory
	err = coll.Find(c, filter).Sort("-updateAt").All(&items)
	utils.CheckError(err, "Query exception")
	app.ResponseSuccess("", items)
}

func getHistory(c *gin.Context) {
	// 生成令牌
	var (
		app = response.Gin{C: c}
		req = vo.ReqId{}
	)
	err := c.ShouldBindUri(&req)
	utils.CheckError(err, "Parameter exception")

	cli, err := qmgo.Open(c, &qmgo.Config{Uri: cf.Mongodb.URL, Database: cf.Mongodb.DataBase, Coll: "commhistory", Auth: &qmgo.Credential{
		AuthMechanism: cf.Mongodb.AuthMechanism,
		Username:      cf.Mongodb.UserName,
		Password:      cf.Mongodb.Password,
		PasswordSet:   cf.Mongodb.PasswordSet,
	}})
	defer func() {
		if err = cli.Close(c); err != nil {
			panic(err)
		}
	}()
	if err != nil {
		utils.CheckError(err, "mongodb connection exception")
		return
	}

	id, err := primitive.ObjectIDFromHex(req.Id)
	utils.CheckError(err, "id resolution exception")
	// 查询条件
	filter := bson.M{
		"_id": id,
	}
	// 查询一个文档
	one := logic.BaseInfo{}
	err = cli.Find(c, filter).One(&one)
	utils.CheckError(err, "mongodb connection exception")

	app.ResponseSuccess("Query success", one)
}

// isAllowedFileType 检查文件后缀是否允许上传
func isAllowedFileType(filename string) bool {
	allowedFileTypes := map[string]bool{
		".xlsx": true, // Excel 文件
		".xls":  true,
		".docx": true, // Word 文件
		".doc":  true,
		".pdf":  true, // PDF 文件
	}

	ext := strings.ToLower(filepath.Ext(filename))
	return allowedFileTypes[ext]
}
