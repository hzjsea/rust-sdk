// #!  global
// #![warn()] enable
// #![allow()] disable
#![allow(non_snake_case)]
#![allow(dead_code)]
use hmac::Hmac;
use http::method;
use openssl::{hash, pkcs5::pbkdf2_hmac};
use reqwest::Client;
use std::{borrow::Borrow, collections::{HashMap, VecDeque}, default, ops::Index};
use std::{fs::File, usize};
// use sha::{Sha1, sha1};
use std::str::from_utf8;
// use hmac::{Hmac, Mac, NewMac};
use chrono::Utc;
use crypto::{digest::Digest, hmac, mac::Mac, md5, sha1};
use hyper::{Request, header::Keys, http};
use log::{info}


#[derive(Default,Debug)]
struct UpYunConfig {
    Bucket: String,
    Operator: String,
    Password: String,
    Secret: String,
    Hosts: HashMap<String, String>,
    UserAgent: String,
}
#[derive(Default,Debug)]
struct UpYun {
    UpYunConfig: UpYunConfig,
    httpc: String,
    deprecated: bool,
}

#[derive(Default)]
struct RestReqConfig {
    method: String,
    uri: String,
    query: String,
    headers: HashMap<String, String>,
    closeBody: bool,
    httpBody: String,
    useMD5: bool,
}

#[derive(Default)]
struct RestAuthConfig {
    method: String,
    uri: String,
    DateStr: String,
    LengthStr: String,
}

#[derive(Default,Debug)]
struct PutObjectConfig {
    path: String,
    local_path: String,
    reader: Vec<u8>,
    headers: HashMap<String,String>,
    use_md5: bool,
    user_resume_upload: bool,
    resume_partsize: i64,
    max_resume_put_tries: i32,
}


impl  PutObjectConfig {
    fn new() -> Self{
        PutObjectConfig{
            ..Default::default()
        }
    }

    fn build(self) -> Self{
        self
    }


    fn set_path(mut self, path: String) -> Self{
       self.path = path;
       self
    }

    fn set_local_path(mut self, local_path: String) -> Self{
        self.local_path = local_path;
        self
    }
}

impl RestReqConfig {
    fn new() -> Self {
        RestReqConfig {
            ..Default::default()
        }
    }

    fn set_method(mut self, method: String) -> Self {
        self.method = method;
        self
    }

    fn set_uri(mut self, uri: String) -> Self {
        self.uri = uri;
        self
    }

    fn set_query(mut self, query: String) -> Self {
        self.query = query;
        self
    }

    fn set_headers(mut self, headers: HashMap<String, String>) -> Self {
        self.headers = headers;
        self
    }

    fn set_close(mut self, close: bool) -> Self {
        self.closeBody = close;
        self
    }

    fn set_usemd5(mut self, usemd5: bool) -> Self {
        self.useMD5 = usemd5;
        self
    }

    fn build(self) -> Self {
        self
    }
}

impl UpYunConfig {
    fn new(Bucket: String, Operator: String, Password: String) -> Self{
        UpYunConfig{
            Bucket:Bucket,
            Operator:Operator,
            Password: Password,
            ..Default::default()
        }
    }

    fn build(mut self) -> Self {
        self
    }
}


impl UpYun {
    fn new(config: UpYunConfig) -> Self{
        // init upyunconfig
        UpYun{
            UpYunConfig: config,
            ..Default::default()
        }
    }

    fn set_httpc(mut self) -> Self{
        self.httpc = "".to_string();
        self
    }

    fn set_deprecated(mut self) -> Self{
        self.deprecated = true;
        self
    }

    fn build(self) -> Self{
        self
    }


    // func (up *UpYun) Put(config *PutObjectConfig) (err error) {
    //     if config.LocalPath != "" {
    //         var fd *os.File
    //         if fd, err = os.Open(config.LocalPath); err != nil {
    //             return errorOperation("open file", err)
    //         }
    //         defer fd.Close()
    //         config.Reader = fd
    //     }
    
    //     if config.UseResumeUpload { // 是否在用断点续传
    //         logrus.Info("up.resumePut")
    //         return up.resumePut(config)
    //     } else {
    //         logrus.Info("up.put") // 正常上传
    //         return up.put(config)
    //     }
    // }

    fn Put(&mut self, config: PutObjectConfig){
        if config.local_path != ""{
            // file
        }
        
        if config.user_resume_upload{
            // 断电续传
            info!("断电续传尚未完成")
        } else {
            info!("正常上传")
        }
    }


    fn put_file(
        &mut self,
        file_path: String,
        filepath: String,
    ) -> Result<(), Box<dyn std::error::Error>> {
        if file_path != "" {
            match File::open(filepath) {
                Ok(file) => {
                    println!("{:?}", file)
                }
                Err(e) => {
                    println!("open file error{:?}", e)
                }
            }
        }
        Ok(())
    }

    fn doGetEndpoint(&mut self, host: String) -> String {
        match self.UpYunConfig.Hosts.get(&host){
            Some(Value ) => Value.to_string(),
            None => host
        }
        
    }

    /// FIXME
    fn doHTTPRequest(&mut self,method: hyper::Method, url:String, headers: HashMap<String,String>, body: Vec<u8>){
        match  hyper::Request::builder().method(method).uri(url).body(body){
            Ok(req) => {
                for (key,value) in headers{
                    if key.to_lowercase() == "host"{
                        // req.
                    } else {
                    }
                }
            },
            Err(e) => {
                println!("{:?}",e)
            }
        }
    }

    fn MakeRESTAuth(&mut self,config: RestAuthConfig) -> String{
        let sign = vec![config.method, config.uri, config.DateStr, config.LengthStr, self.UpYunConfig.Password.clone()];
        let mut tt = vec![];
        tt.push(String::from("Upyun"));
        tt.push(self.UpYunConfig.Operator.clone());
        tt.push(":".to_string());
        tt.push(md5str(sign.join("&")));
        tt.concat()

    }

    fn doRESTRequest(&mut self, config: &RestReqConfig) -> Result<(), Box<dyn std::error::Error>> {
        // 这里传入的uri做了编码 utf-8 转成 ascii 的组合 /sdk-test/xx/%E4%B8%AD%E6%96%87.log
        // escUri := path.Join("/", up.Bucket, escapeUri(config.uri))
        let mut escUri =
            String::from("/") + &self.UpYunConfig.Bucket + &escapeUri(config.uri.clone());

        if config.uri.chars().last().unwrap() == '/' {
            escUri += '/'.to_string().as_str()
        }

        if config.query != "" {
            escUri += ("?".to_owned() + &config.query).as_str()
        }

        let mut headers: HashMap<String, String> = HashMap::new();
        let mut has_md5: bool = false;

        let old_header: HashMap<String, String> = HashMap::new();

        for (k, v) in old_header {
            if k.to_lowercase() == "content-md5" && v != "" {
                has_md5 = true
            }
            headers.insert(k, v).expect("header set error ");
        }

        headers.insert("Date".to_string(), makeRFC1123Date());
        headers.insert("Host".to_string(), "v0.api.upyun.com".to_string()); // 为什么这个是固定的

        if !has_md5 && config.useMD5 {
            // config.httpBody.
            // 这里需要判断下httpBody的类型
            //// FIXME: depend on config.httpBody.type
            headers.insert("Content".to_string(), "xx".to_string());
        }

        if self.deprecated {
            if let Some(value) = headers.get("Conetnt-Length") {
                let size = 0;
            }

        }

        Ok(())
    }
}

fn md5str(s: String) -> String {
    let mut hasher = md5::Md5::new();
    hasher.input_str(&s);
    hasher.result_str()
}

fn escapeUri(s: String) -> String {
    // let s = String::from("/xx/中文.log");
    if s == "" {
        let _s = String::from("中文");
    }
    let escape: [u32; 8] = [
        0xffffffff, 0xfc001fff, 0x78000001, 0xb8000001, 0xffffffff, 0xffffffff, 0xffffffff,
        0xffffffff,
    ];
    let hexMap = "0123456789ABCDEF".as_bytes();

    let mut size = 0;
    let ss = s.as_bytes();
    for i in 0..ss.len() {
        let c = ss[i];
        if escape.get((c >> 5) as usize).unwrap() & (1 << (c & 0x1f)) > 0 {
            size += 3
        } else {
            size += 1
        }
    }

    // let ret = [0u8;size]; //  静态 error
    let mut ret = vec![0u8; size]; // 动态 success
    let mut j = 0;
    for i in 0..ss.len() {
        let c = ss[i];
        if escape[(c >> 5) as usize] & (1 << (c & 0x1f)) > 0 {
            ret[j] = "%".as_bytes()[0];
            // ret[j] = "%".parse::<u8>().unwrap();
            ret[j + 1] = hexMap[(c >> 4) as usize];
            ret[j + 2] = hexMap[(c & 0xf) as usize];
            j += 3
        } else {
            ret[j] = c;
            j += 1
        }
    }
    from_utf8(&ret).unwrap().to_string()
}

fn unescapeUri(s: String) -> String {
    println!("============");
    // 定位 % 转换成byte的数
    // let xx = "%";
    // let xxx = xx.as_bytes();
    // println!("change % to byte is ==> {:?}",xxx);

    // 将传进来的字符串变成 字符数组
    // 遍历 匹配  %

    // if i+2 >= len(s) || !ishex(s[i+1]) || !ishex(s[i+2]) {
    //     // if not correct, return original string
    //     return s
    // }
    // i += 3
    let mut n: i32 = 0;
    let s_vec: Vec<char> = s.chars().collect();
    for mut _i in 0..s_vec.len() {
        if s_vec[_i] == '%' {
            if _i + 2 >= s_vec.len() || !ishex(s_vec[_i + 1] as u8) || !ishex(s_vec[_i + 2] as u8) {
                return s;
            }
            _i += 3
        } else {
            _i += 1
        }
        n += 1
    }

    let mut t_vec: Vec<u8> = Vec::new();
    let mut j = 0;

    for mut _i in 0..s_vec.len() {
        if s_vec[_i] == '%' {
            t_vec[j] = unhex(s_vec[_i + 1] as u8) << 4 | unhex(s_vec[_i + 2] as u8);
            _i += 3
        } else {
            t_vec[j] = s_vec[_i] as u8;
            _i += 1
        }
        j += 1
    }

    from_utf8(&t_vec).unwrap().to_string()
}

// 16进制 to 10进制
fn unhex(c: u8) -> u8 {
    if '0' as u8 <= c && c <= '9' as u8 {
        c - '0' as u8
    } else if 'a' as u8 <= c && c <= 'f' as u8 {
        c - 'a' as u8 + 10
    } else if 'A' as u8 <= c && c <= 'F' as u8 {
        c - 'A' as u8 + 10
    } else {
        0
    }
}

// 判断是否为16进制
fn ishex(c: u8) -> bool {
    if '0' as u8 <= c && c <= '9' as u8 {
        true
    } else if 'a' as u8 <= c && c <= 'f' as u8 {
        true
    } else if 'A' as u8 <= c && c <= 'F' as u8 {
        true
    } else {
        false
    }
}

// 使用sha-1加密内容 在hmac 一下
// func hmacSha1(key string, data []byte) []byte {
//     hm := hmac.New(sha1.New, []byte(key))
//     hm.Write(data)
//     return hm.Sum(nil)
// }
fn hmacSha1(key: &[u8], value: &[u8]) -> String {
    // // 先把秘钥加密一下 类似md5 只是算法不同
    // let mut hasher = crypto::sha1::Sha1::new();
    // hasher.input_str(&key);
    // let result = hasher.result_str().as_bytes();
    // let rr = vec![0u8;20];
    // rr.copy_from_slice(&result);

    // 再把加密后的内容和value 一起hmac一下
    // let h_mac = NewMac::new(&result)

    let mut mac = hmac::Hmac::new(crypto::sha1::Sha1::new(), key);
    mac.input(value);
    let result = mac.result();
    let code = result.code();
    // The correct hash is returned, it's just not in the representation you expected. The hash is returned as raw bytes, not as bytes converted to ASCII hexadecimal digits.
    // If we print the hash code array as hex, like this
    // println!("{:02x?}", code);
    let code_vec = code
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect::<Vec<String>>();
    code_vec.concat()
}

// func makeRFC1123Date(d time.Time) string {
// 	utc := d.UTC().Format(time.RFC1123)
// 	return strings.ReplaceAll(utc, "UTC", "GMT")
// }

fn makeRFC1123Date() -> String {
    let time = Utc::now();
    let time_utc = time.to_rfc2822();
    let new_time_utf = time_utc.replace("+0000", "GMT");
    new_time_utf
}

// base64 to string

// base64::decode_block(src)

#[cfg(test)]
mod tests {
    use chrono::{Date, DateTime, Utc};
    use hyper::http;
    use std::{collections::HashMap, io::Read};

    use crate::escapeUri;
    use crate::hmacSha1;
    use crate::makeRFC1123Date;

    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }

    #[test]
    fn parse_uri() {
        let bucket = String::from("sdk-test");
        let config = "/xx/中文.log/".to_string();
        let query = "xxx";
        let mut escUri = String::from("/") + &bucket + &escapeUri("/xx/中文.log".to_string());
        if config.chars().last().unwrap() == '/' {
            escUri += '/'.to_string().as_str()
        }

        if query != "" {
            escUri += ("?".to_owned() + query).as_str()
        }

        // header set
        // hasmd5 set
        let mut headers: HashMap<String, String> = HashMap::new();
        let mut has_md5: bool = false;

        let old_header: HashMap<String, String> = HashMap::new();

        for (k, v) in old_header {
            if k.to_lowercase() == "content-md5" && v != "" {
                has_md5 = true
            }
            headers.insert(k, v).expect("header set error ");
        }

        headers.insert("Date".to_string(), makeRFC1123Date());
        headers.insert("Host".to_string(), "v0.api.upyun.com".to_string()); // 为什么这个是固定的

        // headers["Date"] = makeRFC1123Date(time.Now());
        // headers["Host"] = "v0.api.upyun.com"

        if !has_md5 {
            // 判断类型
        }
        let deprecated = "";
        // if deprecated {}
        if let Some(value) = headers.get("Content-Length") {
            let size = 0;
        }
    }

    // use crate::base64ToStr;
    #[test]
    fn make_unified_auth() {
        let sign: Vec<&'static str> = vec!["method", "uri", "DateStr", "Policy", "ContentMD5"];

        let mut sign_no_empty: Vec<String> = Vec::new();
        for item in sign {
            if item != "" {
                sign_no_empty.push(item.to_string());
            }
        }

        let sign_bytes = sign_no_empty.join("&");
        let password = "xx".as_bytes();
        let sign_str =
            openssl::base64::encode_block(hmacSha1(password, sign_bytes.as_bytes()).as_bytes());

        let back_vec: Vec<String> = vec![
            "Upyun".to_string(),
            "Operator".to_string(),
            ":".to_string(),
            sign_str,
        ];
        let _back_str = back_vec.concat();
    }

    #[test]
    fn hmac_test() {
        let value = "xx".as_bytes();
        let key = "yy".as_bytes();
        assert_eq!(
            "3124cf1daef6d713c312065988652d8b7fca587e".to_string(),
            hmacSha1(key, value)
        )
    }

    #[test]
    fn makeRFC1123Date_test() {
        let time = Utc::now();
        let time_utc = time.to_rfc2822();
        let new_time_utf = time_utc.replace("+0000", "GMT");
        println!("{:?}", new_time_utf);
    }

    use crypto::{digest::Digest, md5::Md5};
    #[test]
    fn md5str() {
        // 关于md5需要介绍的东西
        // 因为直接md5转换后得到的东西会很长， 所以一般会把它/4 也就是算一个16进制
        let s = "xx".to_string();

        // create
        let mut hasher = Md5::new();
        hasher.input_str(&s);
        let xx = hasher.result_str();
        println!("{:?}", xx);
    }

    // using hyper
    #[test]
    fn hyper_test(){
        let method = http::Method::GET;
        let url = "http://www.baidu.com";
        let headers: HashMap<String, String> = HashMap::new();
        let body = [0u8;32];
        match hyper::Request::builder().method(method).uri(url).body(body){
            Ok(req) => {
                for (key,value) in headers{
                    println!("{:?}{:?}",&key, &value);
                    if key.to_lowercase() == "host"{
                        // req.
                    } else {
                        println!("{:?}", req.headers())

                    }
                }
            },
            Err(e) => {
                println!("{:?}",e)
            }
        }
    }

}

fn main() {
    let BUCKET = "sdk-test".to_string();
    let CNAME = "sdk-test.b0-aicdn.com".to_string();
    let USER = "sdk".to_string();
    let PASSWORD = "IwwEqRmUgs29IdNOzDT3ePFz7Q9iMT5m".to_string();
    //
    let up = UpYun::new(UpYunConfig::new(BUCKET, USER, PASSWORD).build()).build();
    let put_object_config = PutObjectConfig::new().set_local_path("".to_string()).set_path("/xx/中文.log".to_string()).build();
    
    println!("{:?}",up);




    // let rqc = RestReqConfig::new()
    //     .set_uri("/xx/中文.log".to_string())
    //     .build();
}
