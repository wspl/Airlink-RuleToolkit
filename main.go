package main

import (
	"gopkg.in/gin-gonic/gin.v1"
)

func main() {

	app := gin.Default()
	app.GET("/", func(ctx *gin.Context) {
		ctx.String(200, "Hello Airlink-RuleToolkit")
	})
	app.GET("/convert", func(ctx *gin.Context) {
		clsr := newRemoteClassicRule(ctx.Query("url"))
		alr := newAirlinkRuleByClassic(ctx.Query("name"), clsr)
		ctx.String(200, alr.body)
	})
	app.Run(":3000")
}