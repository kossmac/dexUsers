package main

import (
	"context"
	"embed"
	"fmt"
	"github.com/dexidp/dex/api/v2"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"html/template"
	"log/slog"
	"net/http"
)

//go:embed html/*.tmpl
var f embed.FS

func newDexClient(hostAndPort string) (api.DexClient, error) {
	conn, err := grpc.NewClient(hostAndPort, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return nil, fmt.Errorf("dial: %v", err)
	}
	return api.NewDexClient(conn), nil
}

func main() {
	gin.SetMode(gin.ReleaseMode)
	slog.SetLogLoggerLevel(-4)

	client, err := newDexClient("127.0.0.1:5557")
	if err != nil {
		slog.Error("failed creating dex client: %v ", err)
	}

	r := gin.Default()
	r.SetHTMLTemplate(template.Must(template.New("").ParseFS(f, "html/*.tmpl")))

	r.GET("/", func(c *gin.Context) {
		resp, err := client.ListPasswords(context.TODO(), &api.ListPasswordReq{})
		if err != nil {
			slog.Error("failed to list password:", slog.String("msg", err.Error()))
			c.HTML(503, "error.tmpl", gin.H{
				"error": err.Error(),
			})
		} else {
			c.HTML(http.StatusOK, "index.tmpl", gin.H{
				"passwords": resp.Passwords,
			})
		}
	})

	r.POST("/add", func(c *gin.Context) {
		hash, _ := bcrypt.GenerateFromPassword([]byte(c.PostForm("password")), 10)

		addReq := &api.CreatePasswordReq{
			Password: &api.Password{
				Email:    c.PostForm("email"),
				Username: c.PostForm("username"),
				Hash:     hash,
				UserId:   uuid.NewString(),
			},
		}
		slog.Debug(fmt.Sprintf("creating user %s - %s - %s", addReq.Password.Username, addReq.Password.Email, addReq.Password.Hash))
		msg, err := client.CreatePassword(context.TODO(), addReq)
		if err != nil {
			fmt.Println(msg)
		}

		c.Redirect(http.StatusFound, "/")
	})

	r.POST("/delete", func(c *gin.Context) {
		email := c.PostForm("email")
		deleteReq := &api.DeletePasswordReq{Email: email}
		client.DeletePassword(context.TODO(), deleteReq)

		c.Redirect(http.StatusFound, "/")
	})

	err = r.Run(":8080")
	if err != nil {
		slog.Error("failed running server:", slog.String("msg", err.Error()))
	}
}
