# BiuPass 网页版（只读）

打开地址：https://lecster2.github.io/biupass-web/

这是密码生成器 BiuPass 的网页查看器：在 iPhone / 其他电脑的浏览器里，打开电脑版导出的**加密备份**，
用恢复密钥（或这台设备上登记的 Face ID / 指纹）解锁后查看、复制。

- **这里只有网页程序，没有任何数据。** 保险库文件只在你自己的设备上，在浏览器里解密
- 页面用 CSP `connect-src 'none'` 禁止任何联网：解密后的内容没法被发出去
- 恢复密钥经 Argon2id（256 MB）派生，和电脑版完全相同
- 装好（添加到主屏幕）后**不自动更新**：有新版本时只提示，点「更新」才换
- 只读：修改请在电脑版上进行

第三方代码：`vendor/argon2.umd.min.js` 来自 [hash-wasm](https://github.com/Daninet/hash-wasm) 4.12.0（MIT，见 `vendor/hash-wasm.LICENSE.txt`）。
