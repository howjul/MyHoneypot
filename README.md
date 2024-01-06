# 基于 SSH 的蜜罐

## 1. 实现思路



## 2. 实现步骤



## 3. 实现效果



## 4. 问题解决

- 基于ssh的蜜罐的实现基于linux操作系统，已经在ubuntu中完成测试，如果是其他操作系统比如macOS，那么在跳出终端界面后可能会有意想不到的效果，可能是因为macOS和linux在字符编码上有一定的差异。
- 代码的python版本为3.8.18，macOS可以使用[pyenv](https://zhuanlan.zhihu.com/p/532840161#:~:text=%E5%9C%A8Mac%E4%B8%8A%E8%BF%9B%E8%A1%8CPython%E5%A4%9A%E7%89%88%E6%9C%AC%E5%88%87%E6%8D%A2%201%201%E3%80%81%E5%AE%89%E8%A3%85Homebrew%202,2%E3%80%81%E9%80%9A%E8%BF%87brew%E5%AE%89%E8%A3%85pyenv%203%203%E3%80%81%E4%BD%BF%E7%94%A8pyenv%E5%AE%89%E8%A3%85Python3%204%204%E3%80%81%E8%A7%A3%E5%86%B3Python%E7%94%A8pip%E5%91%BD%E4%BB%A4%E5%AE%89%E8%A3%85%E9%80%9F%E5%BA%A6%E6%85%A2%EF%BC%8C%E6%94%B9%E7%94%A8%E5%9B%BD%E5%86%85%E9%95%9C%E5%83%8F)来进行版本的切换，而linux中可以从[deadsnakes PPA](https://blog.csdn.net/qq_51116518/article/details/130184514)中下载指定版本的python并设置为默认的python版本（注意，这里可能会有一些网络的问题，可能需要使用一些[国内镜像](https://www.jianshu.com/p/3a030350d2cd)），之后使用这个版本的python[下载对应的pip](https://blog.csdn.net/bubudezhuren/article/details/130949037)，再运行`pip3 install -r requirements.txt`即可完成环境配置。
- 由于程序需要监听22号端口，需要提高权限来运行脚本，这时候可能会出现错误。
