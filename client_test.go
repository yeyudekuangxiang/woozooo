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
	cookie := "_uab_collina=173322184494655157343584; ylogin=4252785; uag=484dd8338c1aa17a93892fbca7e9f371; PHPSESSID=4ee4245qshp0n4v0hd9fppdpjthm8sl2; __51cke__=; phpdisk_info=V2cFNQNkAjwANVM7XDNQAwVhBA8KYlw8DzpUNgQ2AjgAMl5pBGMNMwEzVQxeZgY%2FAWdVNAFuUTdQYAI3B2UDNVdiBTYDNAJoADdTMVxlUGwFZgQxCmBcPQ86VD0EMQJkADVeOgQ1DTUBNFU8Xg0GbQFmVWEBalEyUGsCZAc0AzRXYQU3; tfstk=g0R-IBTajmmuBqCiZbMcxCxTwW0mnBLPH38_tMjudnKv8HWQq_fodHKX09OlZUxA9HtFq8YhxKLB4etdL4ShAMKHRL0msfYyz65Bvccissuk8ht8O7NIRS_1WqbSXXvrW65Ijm20OTlOThRlcZRWlqQh-w_WAa_jkwbRO76QN-Zf0w1CO81Qct_CRua5AHTjkwSfA66SBxhRYDsa9pDB3J9IxwVQOIQRhxYRcDvvgaBRfUO8OWg1yTI6Pina2vZfheWpTyPdcU9wYNt7VDIeMEOWChi0Eg9OJFvpf22Po9dPMgOKW5fkaU91dCiUdhCJvOO5HyN5GssPMZOs-RSDMgxBwtgg69fXsO1WnxolK_Q9AQ-8JWt6oFAP3BnTcMJl7s_pTVwdv9syMCAt18qGXw2SkqeULT_2Uaf9vfTuYc_Ajqj0LJWvbZIikqeULT_VkG00nJyFHh5..; folder_id_c=-1; __tins__21412745=%7B%22sid%22%3A%201734594608129%2C%20%22vd%22%3A%201%2C%20%22expires%22%3A%201734596408129%7D; __51laig__=16"
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
