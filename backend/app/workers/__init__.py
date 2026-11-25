"""后台任务消费者层包。

本包负责从 Redis 队列消费任务并异步执行：
- worker.py：Redis 队列消费者（brpop 阻塞消费 task_queue）
- task_executor.py：任务执行器（编排五阶段流水线）
- report_pdf_worker.py：PDF 转换独立 worker（从单独队列消费）
"""
