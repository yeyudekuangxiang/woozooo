package woozooo

import (
	"github.com/stretchr/testify/require"
	"log"
	"strconv"
	"strings"
	"testing"
	"time"
)

func client() *Client {
	domain := "https://pc.woozooo.com/"
	cookie := "set cookie"
	c, err := NewClient(domain, cookie)
	if err != nil {
		log.Panic(err)
	}
	return c
}
func TestReadDir(t *testing.T) {
	c := client()
	resp, err := c.ReadSubDir(ReadSubDirReq{
		DirId: -1,
	})
	require.Equal(t, nil, err)
	require.Equal(t, 1, resp.Zt)
	t.Logf("resp:%+v\n", resp)
}
func TestReadFile(t *testing.T) {
	c := client()
	resp, err := c.ReadFile(ReadFileReq{
		DirId: -1,
		Page:  1,
	})
	require.Equal(t, nil, err)
	require.Equal(t, 1, resp.Zt)
	t.Logf("resp:%+v\n", resp)
}
func TestMkdir(t *testing.T) {
	c := client()
	resp, err := c.Mkdir(MkdirReq{
		ParentId:          -1,
		FolderName:        strconv.FormatInt(time.Now().Unix(), 10),
		FolderDescription: "lmqwleqw",
	})
	require.Equal(t, nil, err)
	require.Equal(t, int64(1), resp.Zt)
	t.Logf("resp:%+v\n", resp)
}
func TestUpload(t *testing.T) {
	c := client()
	resp, err := c.UploadFile("C:\\Users\\yeyud\\Downloads\\tlyh.flac", -1)
	require.Equal(t, nil, err)
	require.Equal(t, 1, resp.Zt)
	t.Logf("resp:%+v\n", resp)
}
func TestShareInfo(t *testing.T) {
	c := client()
	resp, err := c.ShareInfo(ShareInfoReq{
		FileId: 214208012,
	})
	require.Equal(t, nil, err)
	require.Equal(t, 1, resp.Zt)
	t.Logf("resp:%+v\n", resp)
}
func TestDownInfo(t *testing.T) {
	c := client()
	resp, err := c.DownInfo(214243697)
	require.Equal(t, nil, err)
	require.Equal(t, 1, resp.Zt)
	t.Logf("resp:%+v\n", resp)
}
func TestUploadReader(t *testing.T) {
	c := client()
	resp, err := c.UploadFileFromReader(strings.NewReader("123123123"), "aaa.txt", -1)
	require.Equal(t, nil, err)
	require.Equal(t, 1, resp.Zt)
	t.Logf("resp:%+v\n", resp)
}
