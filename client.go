package woozooo

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/yeyudekuangxiang/common-go/tool/httptool"
	"io"
	"log"
	"mime/multipart"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"path"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

type Client struct {
	htpClient   *httptool.HttpClient
	uid         string
	vei         string
	lastVeiTime *time.Time
	lock        sync.Mutex
}

const Domain = "https://up.woozooo.com/"
const CookieDomain = "woozooo.com"

func NewClient() (*Client, error) {
	jar, err := cookiejar.New(nil)
	if err != nil {
		return nil, err
	}
	client := &http.Client{
		Jar:     jar,
		Timeout: time.Minute * 5,
	}
	logger := httptool.WithLogger(httptool.FuncLogger(func(data httptool.LogData, err error) {

	}))
	return &Client{
		htpClient: httptool.NewHttpClient(client, logger),
	}, nil
}

// Login 淘宝滑动验证码未解决
func (c *Client) Login(phone, password string) error {
	body, err := c.htpClient.Get("https://up.woozooo.com/account.php?action=login")
	if err != nil {
		return err
	}
	getFormValue := func(name string) (string, error) {
		reg, err := regexp.Compile(fmt.Sprintf(`<input.*?name="%s".*?value="(.*)".*?>`, name))
		if err != nil {
			return "", err
		}
		matchList := reg.FindStringSubmatch(string(body))
		if len(matchList) != 2 {
			return "", nil
		}
		return matchList[1], nil
	}
	action, err := getFormValue("action")
	if err != nil {
		return err
	}
	task, err := getFormValue("task")
	if err != nil {
		return err
	}
	ref, err := getFormValue("ref")
	if err != nil {
		return err
	}
	setSessionId, err := getFormValue("setSessionId")
	if err != nil {
		return err
	}
	setToken, err := getFormValue("setToken")
	if err != nil {
		return err
	}
	setSig, err := getFormValue("setSig")
	if err != nil {
		return err
	}
	setScene, err := getFormValue("setScene")
	if err != nil {
		return err
	}
	formhash, err := getFormValue("formhash")
	if err != nil {
		return err
	}

	info := url.Values{
		"action":       {action},
		"task":         {task},
		"ref":          {ref},
		"setSessionId": {setSessionId},
		"setToken":     {setToken},
		"setSig":       {setSig},
		"setScene":     {setScene},
		"formhash":     {formhash},
		"username":     {phone},
		"password":     {password},
	}

	result, err := c.htpClient.OriginForm("https://up.woozooo.com/account.php", "POST", []byte(info.Encode()))
	if err != nil {
		return err
	}
	scs := result.Response.Header.Values("Set-Cookie")
	for _, sc := range scs {
		parts := strings.Split(sc, "=")
		if parts[0] == "ylogin" {
			parts2 := strings.Split(parts[1], ";")
			c.uid = strings.TrimSpace(parts2[0])
			break
		}
	}
	return nil
}
func (c *Client) SetCookie(cookieStr string) error {
	cks, err := http.ParseCookie(cookieStr)
	if err != nil {
		return err
	}
	for _, ck := range cks {
		ck.Domain = CookieDomain
		if ck.Name == "ylogin" {
			c.uid = ck.Value
		}
	}
	uInfo, err := url.Parse(Domain)
	if err != nil {
		return err
	}
	c.htpClient.GetClient().Jar.SetCookies(uInfo, cks)
	return nil
}
func (c *Client) Mkdir(req MkdirReq) (*MkdirResp, error) {
	body, err := c.postForm(Domain+"/doupload.php?uid="+c.uid, req)
	if err != nil {
		return nil, err
	}
	resp, err := jsonUnmarshal[mkdirResp](body)
	if err != nil {
		return nil, err
	}
	return &MkdirResp{
		Zt:   resp.Zt,
		Text: convert2string(resp.Text),
		Info: convert2string(resp.Info),
	}, nil
}

// ReadSubDir 获取文件夹列表
func (c *Client) ReadSubDir(req ReadSubDirReq) (*ReadSubDirResp, error) {
	vei, err := c.getVei()
	if err != nil {
		return nil, err
	}
	req.vei = vei
	body, err := c.postForm(Domain+"/doupload.php?uid="+c.uid, req)
	if err != nil {
		return nil, err
	}
	return jsonUnmarshal[ReadSubDirResp](body)
}

// ReadFile 获取文件列表
func (c *Client) ReadFile(req ReadFileReq) (*ReadFileResp, error) {
	vei, err := c.getVei()
	if err != nil {
		return nil, err
	}
	req.vei = vei
	body, err := c.postForm(Domain+"/doupload.php?uid="+c.uid, req)
	if err != nil {
		return nil, err
	}
	return jsonUnmarshal[ReadFileResp](body)
}
func (c *Client) ShareInfo(req ShareInfoReq) (*ShareInfoResp, error) {
	body, err := c.postForm(Domain+"/doupload.php", req)
	if err != nil {
		return nil, err
	}
	return jsonUnmarshal[ShareInfoResp](body)
}
func (c *Client) DownInfo(fileId int64) (*DownInfoResp, error) {
	// 获取分享连接
	shareInfoResp, err := c.ShareInfo(ShareInfoReq{
		FileId: fileId,
	})
	if err != nil {
		return nil, err
	}
	if shareInfoResp.Zt != 1 {
		return nil, fmt.Errorf("获取分享连接失败%v", shareInfoResp)
	}
	/*if strings.Contains(shareInfoResp.Info.IsNewd, "lanzouu.com") {
		uuu, err := getLanRealDown(fmt.Sprintf("%s/%s", shareInfoResp.Info.IsNewd, shareInfoResp.Info.FId))
		if err != nil {
			return nil, err
		}
		uv, err := url.Parse(uuu)
		if err != nil {
			return nil, err
		}
		return &DownInfoResp{
			Zt:  1,
			Dom: fmt.Sprintf("%s://%s", uv.Scheme, uv.Host),
			Url: uv.RequestURI(),
			Inf: "",
		}, nil
	}
	*/
	//获取下载连接
	return c.DownInfoByShareLink(fmt.Sprintf("%s/%s", shareInfoResp.Info.IsNewd, shareInfoResp.Info.FId), shareInfoResp.Info.Pwd)
}
func (c *Client) DownInfoByShareLink(shareLink string, pwd string) (*DownInfoResp, error) {
	// 获取分享页面
	body, err := c.getDownPage(shareLink)
	if err != nil {
		return nil, err
	}
	reg, err := regexp.Compile(`downprocess(.*?)sign':'(.*?)'`)
	if err != nil {
		return nil, err
	}
	list := reg.FindAllStringSubmatch(string(body), -1)
	if len(list) != 3 {
		return nil, errors.New("未获取到签名")
	}
	sign := list[1][2]
	// 获取id
	reg, err = regexp.Compile(`ajaxm.php?file=(.*?)'`)
	if err != nil {
		return nil, err
	}
	list2 := reg.FindStringSubmatch(string(body))
	if len(list2) != 2 {
		return nil, errors.New("未获取到文件id")
	}
	fileId, err := strconv.ParseInt(list2[1], 10, 64)
	if err != nil {
		return nil, err
	}
	//获取下载连接
	return c.downInfoBySign(fileId, sign, pwd)
}
func (c *Client) getVei() (string, error) {
	c.lock.Lock()
	if c.lastVeiTime == nil || time.Now().Sub(*c.lastVeiTime).Seconds() > 3600 {
		body, err := c.get(fmt.Sprintf("%s/mydisk.php?item=files&action=index&u=%s", Domain, c.uid))
		if err != nil {
			return "", err
		}
		reg, err := regexp.Compile(`'vei'.*?'(.*)'`)
		if err != nil {
			return "", err
		}
		list := reg.FindStringSubmatch(string(body))
		if len(list) != 2 {
			return "", fmt.Errorf("获取vei失败")
		}
		c.vei = list[1]
		tm := time.Now()
		c.lastVeiTime = &tm
	}
	c.lock.Unlock()
	return c.vei, nil
}

var mimeMap = map[string]string{
	"doc":          "application/msword",
	"docx":         "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
	"zip":          "application/zip",
	"rar":          "application/vnd.rar",
	"apk":          "application/vnd.android.package-archive",
	"ipa":          "application/octet-stream", // iOS App Package
	"txt":          "text/plain",
	"exe":          "application/vnd.microsoft.portable-executable",
	"7z":           "application/x-7z-compressed",
	"e":            "application/octet-stream", // Custom or unknown
	"z":            "application/x-compress",   // Could be a compressed file
	"ct":           "application/x-cetrainer",  // Cheat Engine Trainer
	"ke":           "application/octet-stream", // Custom or unknown
	"cetrainer":    "application/x-cetrainer",  // Cheat Engine Trainer
	"db":           "application/x-sqlite3",    // SQLite Database
	"tar":          "application/x-tar",
	"pdf":          "application/pdf",
	"w3x":          "application/octet-stream", // Warcraft III Map File
	"epub":         "application/epub+zip",
	"mobi":         "application/x-mobipocket-ebook",
	"azw":          "application/vnd.amazon.ebook",
	"azw3":         "application/vnd.amazon.ebook",
	"osk":          "application/octet-stream", // osu! Skin File
	"osz":          "application/octet-stream", // osu! Beatmap File
	"xpa":          "application/octet-stream", // Could be a patch file
	"cpk":          "application/octet-stream", // Custom or unknown
	"lua":          "text/x-lua",
	"jar":          "application/java-archive",
	"dmg":          "application/x-apple-diskimage",
	"ppt":          "application/vnd.ms-powerpoint",
	"pptx":         "application/vnd.openxmlformats-officedocument.presentationml.presentation",
	"xls":          "application/vnd.ms-excel",
	"xlsx":         "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
	"mp3":          "audio/mpeg",
	"iso":          "application/x-iso9660-image",
	"img":          "application/octet-stream", // Disk Image File
	"gho":          "application/octet-stream", // Norton Ghost Image File
	"ttf":          "font/ttf",
	"ttc":          "font/collection",
	"txf":          "application/octet-stream", // Could be a custom font or texture file
	"dwg":          "image/vnd.dwg",
	"bat":          "application/x-msdownload",
	"dll":          "application/x-msdownload",                // Windows DLL
	"crx":          "application/x-chrome-extension",          // Chrome Extension
	"xapk":         "application/vnd.android.package-archive", // Android Package
	"conf":         "text/plain",                              // Configuration File
	"deb":          "application/vnd.debian.binary-package",   // Debian Package
	"rp":           "application/x-rpm",                       // RPM Package (assuming typo for .rpm)
	"rpm":          "application/x-rpm",                       // RPM Package
	"rplib":        "application/octet-stream",                // Custom or unknown
	"mobileconfig": "application/x-apple-aspen-config",        // Apple Configuration Profile
	"appimage":     "application/octet-stream",                // Linux AppImage
	"lolgezi":      "application/octet-stream",                // Custom or unknown
	"flac":         "audio/flac",                              // FLAC Audio
	"cad":          "application/octet-stream",                // Custom or unknown, could be CAD file
	"hwt":          "application/octet-stream",                // Huawei Theme File
	"accdb":        "application/msaccess",                    // Microsoft Access Database
	"ce":           "application/octet-stream",                // Custom or unknown
	"xmind":        "application/vnd.xmind.workbook",          // XMind Workbook
	"enc":          "application/octet-stream",                // Encrypted File
	"bds":          "application/octet-stream",                // Custom or unknown
	"bdi":          "application/octet-stream",                // Custom or unknown
	"ssf":          "application/octet-stream",                // Structured Storage File, or custom
	"it":           "audio/x-it",                              // Impulse Tracker Module
	"pkg":          "application/x-xar",                       // MacOS Installer Package
	"cfg":          "text/plain",                              // Configuration File
}

func (c *Client) UploadFile(filepath string, dirId string) (*UploadFileResp, error) {
	ext := strings.TrimLeft(path.Ext(filepath), ".")
	mime, ok := mimeMap[ext]
	if !ok {
		return nil, errors.New("不允许的文件格式")
	}
	file, errFile10 := os.Open(filepath)
	if errFile10 != nil {
		return nil, errFile10
	}
	defer file.Close()
	fileInfo, err := file.Stat()
	if err != nil {
		return nil, err
	}
	fileInfo.Size()

	// 格式化布局
	layout := "Mon Jan 2 2006 15:04:05 GMT-0700"

	// 格式化时间，不包括时区详细名称
	formattedTime := fileInfo.ModTime().Format(layout)

	// 手动添加时区名称
	chineseTimeZone := "中国标准时间"

	// 输出格式化后的时间，带有时区名称
	modTime := fmt.Sprintf("%s (%s)\n", formattedTime, chineseTimeZone)

	payload := &bytes.Buffer{}
	writer := multipart.NewWriter(payload)
	_ = writer.WriteField("task", "1")
	_ = writer.WriteField("vie", "2")
	_ = writer.WriteField("ve", "2")
	_ = writer.WriteField("id", "WU_FILE_0")
	_ = writer.WriteField("name", path.Base(filepath))
	_ = writer.WriteField("type", mime)
	_ = writer.WriteField("lastModifiedDate", modTime)
	_ = writer.WriteField("size", "218025")
	_ = writer.WriteField("folder_id_bb_n", dirId)

	part10, errFile10 := writer.CreateFormFile("upload_file", filepath)
	_, errFile10 = io.Copy(part10, file)
	if errFile10 != nil {
		return nil, errFile10
	}
	err = writer.Close()
	if err != nil {
		return nil, err
	}

	body, err := c.htpClient.Post(Domain+"/html5up.php", writer.FormDataContentType(), payload, c.fillHeader())
	if err != nil {
		return nil, err
	}
	return jsonUnmarshal[UploadFileResp](body)
}
func (c *Client) UploadFileFromReader(file io.Reader, fileName string, dirId string) (*UploadFileResp, error) {
	ext := strings.TrimLeft(path.Ext(fileName), ".")
	mime, ok := mimeMap[ext]
	if !ok {
		return nil, errors.New("不允许的文件格式")
	}

	// 格式化布局
	layout := "Mon Jan 2 2006 15:04:05 GMT-0700"

	// 格式化时间，不包括时区详细名称
	formattedTime := time.Now().Format(layout)

	// 手动添加时区名称
	chineseTimeZone := "中国标准时间"

	// 输出格式化后的时间，带有时区名称
	modTime := fmt.Sprintf("%s (%s)\n", formattedTime, chineseTimeZone)

	payload := &bytes.Buffer{}
	writer := multipart.NewWriter(payload)
	_ = writer.WriteField("task", "1")
	_ = writer.WriteField("vie", "2")
	_ = writer.WriteField("ve", "2")
	_ = writer.WriteField("id", "WU_FILE_0")
	_ = writer.WriteField("name", path.Base(fileName))
	_ = writer.WriteField("type", mime)
	_ = writer.WriteField("lastModifiedDate", modTime)
	_ = writer.WriteField("size", "218025")
	_ = writer.WriteField("folder_id_bb_n", dirId)

	part10, errFile10 := writer.CreateFormFile("upload_file", path.Base(fileName))
	_, errFile10 = io.Copy(part10, file)
	if errFile10 != nil {
		return nil, errFile10
	}
	err := writer.Close()
	if err != nil {
		return nil, err
	}

	body, err := c.htpClient.Post(Domain+"/html5up.php", writer.FormDataContentType(), payload, c.fillHeader())
	if err != nil {
		return nil, err
	}

	return jsonUnmarshal[UploadFileResp](body)
}
func (c *Client) get(u string) ([]byte, error) {
	opt := httptool.HttpWithHeader("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7")
	body, err := c.htpClient.Get(u, c.fillHeader(), opt)
	if err != nil {
		return nil, err
	}
	return body, nil
}
func convert2string(v interface{}) string {
	switch vv := v.(type) {
	case string:
		return vv
	case int64:
		return strconv.FormatInt(vv, 10)
	case float64:
		return strconv.FormatFloat(vv, 'f', -1, 64)
	case int:
		return strconv.Itoa(vv)
	default:
		return fmt.Sprintf("%v", v)
	}
}

type IFormValue interface {
	Values() url.Values
}

func jsonUnmarshal[T any](data []byte) (*T, error) {
	var v T
	err := json.Unmarshal(data, &v)
	if err != nil {
		return nil, err
	}
	return &v, nil
}
func (c *Client) fillHeader() httptool.RequestOption {
	return func(req *http.Request) {
		req.Header.Add("accept", "application/json, text/javascript, */*; q=0.01")
		req.Header.Add("accept-language", "zh-CN,zh;q=0.9")
		req.Header.Add("cache-control", "no-cache")
		req.Header.Add("origin", "https://pc.woozooo.com")
		req.Header.Add("pragma", "no-cache")
		req.Header.Add("priority", "u=1, i")
		req.Header.Add("referer", "https://pc.woozooo.com/mydisk.php?item=files&action=index&u=4252785")
		req.Header.Add("sec-ch-ua", "\"Google Chrome\";v=\"131\", \"Chromium\";v=\"131\", \"Not_A Brand\";v=\"24\"")
		req.Header.Add("sec-ch-ua-mobile", "?0")
		req.Header.Add("sec-ch-ua-platform", "\"Windows\"")
		req.Header.Add("sec-fetch-dest", "empty")
		req.Header.Add("sec-fetch-mode", "cors")
		req.Header.Add("sec-fetch-site", "same-origin")
		req.Header.Add("user-agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36")
		req.Header.Add("x-requested-with", "XMLHttpRequest")
	}
}
func (c *Client) postForm(u string, vals IFormValue) ([]byte, error) {
	return c.htpClient.PostFrom(u, vals.Values())
}

type MkdirReq struct {
	ParentId          string
	FolderName        string
	FolderDescription string
}

func (m MkdirReq) Values() url.Values {
	return url.Values{
		"task":               []string{"2"},
		"parent_id":          []string{m.ParentId},
		"folder_name":        []string{m.FolderName},
		"folder_description": []string{m.FolderDescription},
	}
}

type MkdirResp struct {
	Zt   int64  `json:"zt"`
	Text string `json:"text"`
	Info string `json:"info"`
}
type mkdirResp struct {
	Zt   int64       `json:"zt"`
	Text interface{} `json:"text"`
	Info interface{} `json:"info"`
}
type ReadSubDirResp struct {
	Zt   int `json:"zt"`
	Info []struct {
		Name      string `json:"name"`
		FolderDes string `json:"folder_des"`
		Folderid  int64  `json:"folderid"`
		Now       int    `json:"now"`
	} `json:"info"`
	Text []DirInfo `json:"text"`
}
type DirInfo struct {
	Onof        string `json:"onof"`
	Folderlock  string `json:"folderlock"`
	IsLock      string `json:"is_lock"`
	IsCopyright string `json:"is_copyright"`
	Name        string `json:"name"`
	FolId       string `json:"fol_id"`
	FolderDes   string `json:"folder_des"`
}
type ReadFileReq struct {
	DirId int64
	vei   string
	Page  int
}

func (r ReadFileReq) Values() url.Values {
	if r.Page == 0 {
		r.Page = 1
	}
	return url.Values{
		"task":      []string{"5"},
		"folder_id": []string{strconv.FormatInt(r.DirId, 10)},
		"vei":       []string{r.vei},
		"pg":        []string{strconv.Itoa(r.Page)},
	}
}

type ReadSubDirReq struct {
	DirId string
	vei   string
}

func (r ReadSubDirReq) Values() url.Values {
	return url.Values{
		"task":      []string{"47"},
		"folder_id": []string{r.DirId},
		"vei":       []string{r.vei},
		//"pg":        []string{strconv.Itoa(r.Page)},
	}
}

type ReadFileResp struct {
	Zt   int        `json:"zt"`
	Info int        `json:"info"`
	Text []FileInfo `json:"text"`
}
type FileInfo struct {
	Icon          string `json:"icon"`
	Id            string `json:"id"`
	NameAll       string `json:"name_all"`
	Name          string `json:"name"`
	Size          string `json:"size"`
	Time          string `json:"time"`
	Downs         string `json:"downs"`
	Onof          string `json:"onof"`
	IsLock        string `json:"is_lock"`
	Filelock      string `json:"filelock"`
	IsCopyright   int    `json:"is_copyright"`
	IsBakdownload int    `json:"is_bakdownload"`
	Bakdownload   string `json:"bakdownload"`
	IsDes         int    `json:"is_des"`
	IsIco         int    `json:"is_ico"`
}
type UploadFileResp struct {
	Zt   int    `json:"zt"`
	Info string `json:"info"`
	Text []struct {
		Icon    string `json:"icon"`
		Id      string `json:"id"`
		FId     string `json:"f_id"`
		NameAll string `json:"name_all"`
		Name    string `json:"name"`
		Size    string `json:"size"`
		Time    string `json:"time"`
		Downs   string `json:"downs"`
		Onof    string `json:"onof"`
		IsNewd  string `json:"is_newd"`
	} `json:"text"`
}
type ShareInfoReq struct {
	FileId int64
}

func (r ShareInfoReq) Values() url.Values {
	return url.Values{
		"task":    []string{"22"},
		"file_id": []string{strconv.FormatInt(r.FileId, 10)},
	}
}

type ShareInfoResp struct {
	Zt   int `json:"zt"`
	Info struct {
		Pwd    string `json:"pwd"`
		Onof   string `json:"onof"`
		FId    string `json:"f_id"`
		Taoc   string `json:"taoc"`
		IsNewd string `json:"is_newd"`
	} `json:"info"`
	Text interface{} `json:"text"`
}
type DownInfoResp struct {
	Zt  int    `json:"zt"`
	Dom string `json:"dom"` //下载的域名和路径 Dom和Url拼接起来为下载路径
	Url string `json:"url"` // 下载的参数
	Inf string `json:"inf"`
}

func (c *Client) getDownPage(u string) ([]byte, error) {
	opt := func(req *http.Request) {
		req.Header.Add("accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7")
		req.Header.Add("accept-language", "zh-CN,zh;q=0.9")
		req.Header.Add("cache-control", "no-cache")
		req.Header.Add("pragma", "no-cache")
		req.Header.Add("priority", "u=0, i")
		req.Header.Add("sec-ch-ua", "\"Google Chrome\";v=\"131\", \"Chromium\";v=\"131\", \"Not_A Brand\";v=\"24\"")
		req.Header.Add("sec-ch-ua-mobile", "?0")
		req.Header.Add("sec-ch-ua-platform", "\"Windows\"")
		req.Header.Add("sec-fetch-dest", "document")
		req.Header.Add("sec-fetch-mode", "navigate")
		req.Header.Add("sec-fetch-site", "none")
		req.Header.Add("sec-fetch-user", "?1")
		req.Header.Add("upgrade-insecure-requests", "1")
		req.Header.Add("user-agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36")
	}
	return c.htpClient.Get(u, opt)
}
func (c *Client) downInfoBySign(fileId int64, skdklds string, pwd string) (*DownInfoResp, error) {
	u := fmt.Sprintf("https://wwrq.lanzouu.com/ajaxm.php?file=%d", fileId)
	payload := strings.NewReader(fmt.Sprintf("action=downprocess&sign=%s&p=%s&kd=1", skdklds, pwd))

	opt := func(req *http.Request) {
		req.Header.Add("accept", "application/json, text/javascript, */*")
		req.Header.Add("accept-language", "zh-CN,zh;q=0.9")
		req.Header.Add("cache-control", "no-cache")
		req.Header.Add("content-type", "application/x-www-form-urlencoded")
		req.Header.Add("origin", "https://wwrq.lanzouu.com")
		req.Header.Add("pragma", "no-cache")
		req.Header.Add("priority", "u=1, i")
		req.Header.Add("referer", "https://wwrq.lanzouu.com/ijako2ii6xjc")
		req.Header.Add("sec-ch-ua", "\"Google Chrome\";v=\"131\", \"Chromium\";v=\"131\", \"Not_A Brand\";v=\"24\"")
		req.Header.Add("sec-ch-ua-mobile", "?0")
		req.Header.Add("sec-ch-ua-platform", "\"Windows\"")
		req.Header.Add("sec-fetch-dest", "empty")
		req.Header.Add("sec-fetch-mode", "cors")
		req.Header.Add("sec-fetch-site", "same-origin")
		req.Header.Add("user-agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36")
		req.Header.Add("x-requested-with", "XMLHttpRequest")
	}

	req, err := http.NewRequest("POST", u, payload)
	if err != nil {
		return nil, err
	}
	opt(req)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		b, _ := io.ReadAll(resp.Body)
		log.Println(string(b))
		return nil, errors.New(resp.Status)
	}
	body, err := io.ReadAll(resp.Body)
	//body, err := c.htpClient.Post(u, "application/x-www-form-urlencoded", payload, opt)
	if err != nil {
		return nil, err
	}

	return jsonUnmarshal[DownInfoResp](body)
}
func (c *Client) SetProxy(proxyUrl string) error {
	return c.htpClient.SetProxy(proxyUrl)
}
func (c *Client) Down(downLink string) ([]byte, error) {
	req, err := http.NewRequest("GET", downLink, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Add("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7")
	req.Header.Add("Accept-Language", "zh-CN,zh;q=0.9,ja;q=0.8,be;q=0.7")
	req.Header.Add("Cache-Control", "no-cache")
	req.Header.Add("Connection", "keep-alive")
	req.Header.Add("Pragma", "no-cache")
	req.Header.Add("Sec-Fetch-Dest", "document")
	req.Header.Add("Sec-Fetch-Mode", "navigate")
	req.Header.Add("Sec-Fetch-Site", "none")
	req.Header.Add("Sec-Fetch-User", "?1")
	req.Header.Add("Upgrade-Insecure-Requests", "1")
	req.Header.Add("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36")
	req.Header.Add("sec-ch-ua", "\"Not)A;Brand\";v=\"8\", \"Chromium\";v=\"138\", \"Google Chrome\";v=\"138\"")
	req.Header.Add("sec-ch-ua-mobile", "?0")
	req.Header.Add("sec-ch-ua-platform", "\"macOS\"")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if bytes.Contains(data, []byte("系统发现您的网络异常")) {
		return nil, errors.New("网络异常")
	}
	return data, nil
}
func getLanRealDownFromBody(domain string, respBody []byte) (string, error) {

	if len(respBody) == 0 {
		return "", errors.New("body长度为0")
	}
	//log.Println(string(respBody))

	srcReg, err := regexp.Compile(`iframe.*src="(.*?)".*?iframe`)
	if err != nil {
		return "", err
	}
	list := srcReg.FindStringSubmatch(string(respBody))
	if len(list) != 2 {
		return "", errors.New("没有匹配地址")
	}

	//log.Println("网盘下载页", fmt.Sprintf("%s/%s", domain, list[1]))

	downResp, err := http.Get(fmt.Sprintf("%s/%s", domain, list[1]))
	if err != nil {
		return "", err
	}
	defer downResp.Body.Close()
	downBody, err := io.ReadAll(downResp.Body)
	if err != nil {
		return "", err
	}
	//log.Println(string(downBody))

	uReg, err := regexp.Compile(`(/ajaxm.php.*?)'`)
	if err != nil {
		return "", err
	}
	list = uReg.FindStringSubmatch(string(downBody))
	if len(list) != 2 {
		return "", errors.New("未查到ajaxm")
	}
	ajaxUrl := list[1]
	dataReg, err := regexp.Compile(`data.*?:(.*?\})`)
	if err != nil {
		return "", err
	}
	list = dataReg.FindStringSubmatch(string(downBody))
	if len(list) != 2 {
		return "", errors.New("未查到ajaxm参数")
	}
	ajaxBody := list[1]
	ajaxBody = strings.ReplaceAll(ajaxBody, "ajaxdata", `'?ctdf'`)
	ajaxBody = strings.ReplaceAll(ajaxBody, "ciucjdsdc", `''`)
	ajaxBody = strings.ReplaceAll(ajaxBody, "aihidcms", `'7Sij'`)
	ajaxBody = strings.ReplaceAll(ajaxBody, "kdns", `1`)
	ajaxBody = strings.ReplaceAll(ajaxBody, `'`, `"`)
	//log.Println(ajaxUrl, ajaxBody)
	return downAjax(domain, ajaxUrl, ajaxBody)

}
func getLanRealDown(pageUrl string) (string, error) {
	method := "GET"

	client := &http.Client{}
	req, err := http.NewRequest(method, pageUrl, nil)

	if err != nil {
		return "", err
	}
	req.Header.Add("accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7")
	req.Header.Add("accept-language", "zh-CN,zh;q=0.9")
	req.Header.Add("cache-control", "no-cache")
	req.Header.Add("pragma", "no-cache")
	req.Header.Add("priority", "u=0, i")
	req.Header.Add("sec-ch-ua", "\"Google Chrome\";v=\"131\", \"Chromium\";v=\"131\", \"Not_A Brand\";v=\"24\"")
	req.Header.Add("sec-ch-ua-mobile", "?0")
	req.Header.Add("sec-ch-ua-platform", "\"Windows\"")
	req.Header.Add("sec-fetch-dest", "document")
	req.Header.Add("sec-fetch-mode", "navigate")
	req.Header.Add("sec-fetch-site", "none")
	req.Header.Add("sec-fetch-user", "?1")
	req.Header.Add("upgrade-insecure-requests", "1")
	req.Header.Add("user-agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36")

	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	if len(respBody) == 0 {
		return "", fmt.Errorf("body长度为0 %d", resp.StatusCode)
	}
	uu, err := url.Parse(pageUrl)
	if err != nil {
		return "", err
	}
	return getLanRealDownFromBody(fmt.Sprintf("%s://%s", uu.Scheme, uu.Host), respBody)
}
func downAjax(domain, path string, data string) (string, error) {
	uuu := domain + path
	method := "POST"

	m := make(map[string]interface{})
	err := json.Unmarshal([]byte(data), &m)
	if err != nil {
		return "", err
	}
	uv := url.Values{}
	for k, v := range m {
		switch vv := v.(type) {
		case int64:
			uv.Add(k, strconv.FormatInt(vv, 10))
		case string:
			uv.Add(k, vv)
		case float64:
			uv.Add(k, strconv.FormatInt(int64(vv), 10))
		}
	}
	client := &http.Client{}
	//log.Println(uv.Encode())
	req, err := http.NewRequest(method, uuu, strings.NewReader(uv.Encode()))

	if err != nil {
		return "", err
	}
	req.Header.Add("accept", "application/json, text/javascript, */*")
	req.Header.Add("accept-language", "zh-CN,zh;q=0.9")
	req.Header.Add("cache-control", "no-cache")
	req.Header.Add("content-type", "application/x-www-form-urlencoded")
	req.Header.Add("origin", "https://wwrq.lanzouu.com")
	req.Header.Add("pragma", "no-cache")
	req.Header.Add("priority", "u=1, i")
	req.Header.Add("referer", "https://wwrq.lanzouu.com/fn?UjRbMVk2VDFVN1A0AmJSYFc7UGxWPgsvBHcEP1M_bUWdXZFQ3XDQHalMyVzNRNAY1US0FdwM5VjYFcQZpBT5VOlI5W2lZfVQ9VUZQMQI0UiM_c")
	req.Header.Add("sec-ch-ua", "\"Google Chrome\";v=\"131\", \"Chromium\";v=\"131\", \"Not_A Brand\";v=\"24\"")
	req.Header.Add("sec-ch-ua-mobile", "?0")
	req.Header.Add("sec-ch-ua-platform", "\"Windows\"")
	req.Header.Add("sec-fetch-dest", "empty")
	req.Header.Add("sec-fetch-mode", "cors")
	req.Header.Add("sec-fetch-site", "same-origin")
	req.Header.Add("user-agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36")
	req.Header.Add("x-requested-with", "XMLHttpRequest")

	//log.Println("请求ajax", req)
	res, err := client.Do(req)
	//fmt.Println("ajax相应", res, err)
	if err != nil {
		return "", err
	}

	defer res.Body.Close()
	if res.StatusCode != 200 {
		return "", errors.New(res.Status)
	}
	body, err := io.ReadAll(res.Body)
	if err != nil {
		return "", err
	}
	vvv := DownAjaxResp{}
	err = json.Unmarshal(body, &vvv)
	if err != nil {
		return "", err
	}
	if vvv.Zt == 0 {
		return "", fmt.Errorf("%d", vvv.Zt)
	}
	//https://down-load.lanrar.com/file/?BWMBP1tqUmMIAQE5U2ZdMVplVGwFvQaMVuAH5Fe7UOAC5QbZW7cPvwPvUYECuQK/UoBTsFGEApYH6QafVLtWsAWGAftb4FKrCNIBuFO7XdVaLVS3BdAGkla4B55XuFC2AoEG/FvgD/YD2VEpAjACb1JpUzVRKAJmB2kGbFRtVggFbAEyWztSPghnAWRTMl1qWjNUaQViBiJWNwdyVzZQYgIxBmhbNg9vA2FRNAJnAiVSeFMmUTMCMgcwBjJUOlZ4BTQBZ1spUjcIZgF4Uz9dPlpjVDcFYgYwVmMHM1dtUGUCOwYwWzMPbAMwUTICYgI3UjFTZVFoAjAHNgZkVGlWYwVkAWVbMVI1CDsBYlMpXTpabFQwBTkGIlYkB3JXblAjAmsGNVs7D2MDY1E1AmECM1I9U3BRegJpB20GZVRuVmoFNAFhWzVSNwhqAW9TMV1kWjNUYAV0BipWdwdnV2dQJgI/BmBbMQ9oA2RRMwJuAjdSP1NuUTsCJgd1BnBUf1ZqBTQBYFswUj4IaQFnUzVdbFo3VGYFfAZxVjgHcVc2UGACMgZlWygPagNjUT8CeAI2UjFTeFE9AjUHLgYmVGxWOAVyAThbWVJlCDUBalM3
	//"<a href="+dom_down+"/file/"+ date.url + lanosso +" target=_blank rel=noreferrer//><span class=txt>电信下载</span><span class='txt txtc'>联通下载</span><span class=txt>普通下载</span></a>
	return fmt.Sprintf("%s/%s", vvv.Dom, vvv.Url), nil
}

type DownAjaxResp struct {
	Zt  int    `json:"zt"`
	Dom string `json:"dom"`
	Url string `json:"url"`
	Inf int    `json:"inf"`
}
