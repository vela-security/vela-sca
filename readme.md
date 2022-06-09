# vela-sca
vela SCA 软件分析

## vela.sca(tab)
- 启动配置
```lua
local ossindex = "https://ossindex.sonatype.org/api/v3/component-report?token=xxxxxxxxxxxxxxxxxxxxxxxxxxxx"
local s = vela.sca{
  name = "track",
  exe = "share/syft/syft_amd64.exe",
  hash = "xxxxxxxxxxxxxxxxxxxxxxx",
	oss  = ossindex,
	cpe  = "abb.db"
}
```

## sca.cyclonedx(file)
- cdx = sca.cyclonedx(file)
- file 要分析的文件
- cdx.purl
- cdx.cpe
- cdx.group
- cdx.mime
- cdx.copyright
```lua
local cdx = s.cyclonedx("resource/springboot-0.0.1.jar")
cdx.pipe(function(cmt)
    print(cmt.purl)
end)
```

## sca.track(file)
- track = sca.track(file)
- track.cdx
- track.son
```lua
track.son.pipe("vul" , function(s)
  s.range(function(v)
    vela.Debug("vul hit %v" ,v)
    print(v)
  end)
end)

```