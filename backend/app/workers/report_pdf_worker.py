"""PDF 转换独立 worker 模块。

本模块独立处理报告 PDF 转换任务（因为 Playwright 依赖较重）：
- 从 Redis report_pdf_queue 队列消费任务
- 使用 Playwright 无头浏览器将 HTML 报告转为 PDF
- 完成后写入文件路径到 reports 表
- 通过 WebSocket 通知前端导出完成
- 独立队列避免阻塞主任务队列
"""
# TODO: 从 Redis 队列消费 PDF 转换任务
