// 分页组件
//
// 统一的受控分页条，供项目内所有列表页复用。设计要点：
// 1. 左右箭头（首页/上一页/下一页/末页）是独立的真实按钮，点击直接触发翻页；
//    只有在确实到达边界（第 1 页 / 末页）时才禁用。
// 2. 保留"跳至第 N 页"的数字输入跳转，回车与点击按钮均可触发，越界自动收敛。
// 3. 数据不足一页时，明确提示"共 N 条，仅 1 页"，避免用户误以为箭头坏了。
import React, { useEffect, useState } from 'react';
import { Button, InputNumber, Select, Typography } from 'antd';
import {
  DoubleLeftOutlined,
  DoubleRightOutlined,
  LeftOutlined,
  RightOutlined,
} from '@ant-design/icons';

const { Text } = Typography;

/** 页码窗口最多展示的页码按钮数量 */
const MAX_PAGE_BUTTONS = 7;

export interface TablePaginationProps {
  /** 当前页码（从 1 开始） */
  current: number;
  /** 每页条数 */
  pageSize: number;
  /** 总记录数 */
  total: number;
  /** 页码或每页条数变化时触发 */
  onChange: (page: number, pageSize: number) => void;
  /** 可选的每页条数，默认 [10, 20, 50, 100] */
  pageSizeOptions?: number[];
  /** 是否显示每页条数选择器，默认 true */
  showSizeChanger?: boolean;
  /** 自定义总数文案；默认展示"共 n 条 · m 页" */
  showTotal?: (total: number, range: [number, number]) => React.ReactNode;
  /** 是否显示数字跳页输入框，默认 true */
  showQuickJumper?: boolean;
}

type PageItem = number | 'prev-ellipsis' | 'next-ellipsis';

/** 计算总页数，至少 1 页 */
export function calcTotalPages(total: number, pageSize: number): number {
  if (!Number.isFinite(total) || !Number.isFinite(pageSize) || pageSize <= 0) {
    return 1;
  }
  return Math.max(1, Math.ceil(total / pageSize));
}

/** 生成页码按钮序列，页数过多时中间用省略号收敛 */
function buildPageItems(totalPages: number, current: number): PageItem[] {
  if (totalPages <= MAX_PAGE_BUTTONS) {
    return Array.from({ length: totalPages }, (_, index) => index + 1);
  }

  const side = Math.floor((MAX_PAGE_BUTTONS - 3) / 2);
  const start = Math.max(2, current - side);
  const end = Math.min(totalPages - 1, current + side);
  const items: PageItem[] = [1];

  if (start > 2) {
    items.push('prev-ellipsis');
  }
  for (let page = start; page <= end; page += 1) {
    items.push(page);
  }
  if (end < totalPages - 1) {
    items.push('next-ellipsis');
  }
  items.push(totalPages);

  return items;
}

const TablePagination: React.FC<TablePaginationProps> = ({
  current,
  pageSize,
  total,
  onChange,
  pageSizeOptions = [10, 20, 50, 100],
  showSizeChanger = true,
  showTotal,
  showQuickJumper = true,
}) => {
  const totalPages = calcTotalPages(total, pageSize);
  const safeCurrent = Math.min(Math.max(1, current), totalPages);
  const singlePage = totalPages <= 1;

  const [jumpValue, setJumpValue] = useState<number | null>(safeCurrent);

  useEffect(() => {
    setJumpValue(safeCurrent);
  }, [safeCurrent]);

  const goTo = (target: number) => {
    if (!Number.isFinite(target)) {
      return;
    }
    const next = Math.min(Math.max(1, Math.floor(target)), totalPages);
    if (next === safeCurrent) {
      return;
    }
    onChange(next, pageSize);
  };

  const handleJump = () => {
    if (jumpValue === null || !Number.isFinite(jumpValue)) {
      return;
    }
    const next = Math.min(Math.max(1, Math.floor(jumpValue)), totalPages);
    setJumpValue(next);
    if (next !== safeCurrent) {
      onChange(next, pageSize);
    }
  };

  const handleSizeChange = (value: number) => {
    const nextSize = Number(value);
    if (!Number.isFinite(nextSize) || nextSize <= 0) {
      return;
    }
    const nextTotalPages = calcTotalPages(total, nextSize);
    onChange(Math.min(safeCurrent, nextTotalPages), nextSize);
  };

  const rangeStart = total === 0 ? 0 : (safeCurrent - 1) * pageSize + 1;
  const rangeEnd = Math.min(total, safeCurrent * pageSize);

  const totalText = showTotal
    ? showTotal(total, [rangeStart, rangeEnd])
    : `共 ${total} 条 · ${totalPages} 页`;

  const hasPrev = safeCurrent > 1;
  const hasNext = safeCurrent < totalPages;

  return (
    <div
      style={{
        marginTop: 16,
        display: 'flex',
        flexWrap: 'wrap',
        gap: 8,
        alignItems: 'center',
        justifyContent: 'flex-end',
      }}
    >
      <Text type="secondary" style={{ marginRight: 'auto' }}>
        {totalText}
        {singlePage && total > 0 && (
          <Text type="secondary" style={{ marginLeft: 8 }}>
            （数据不足一页，无需翻页）
          </Text>
        )}
      </Text>

      {showSizeChanger && (
        <Select
          size="small"
          style={{ width: 110 }}
          value={pageSize}
          onChange={handleSizeChange}
          options={pageSizeOptions.map((option) => ({
            value: option,
            label: `${option} 条/页`,
          }))}
        />
      )}

      <Button
        size="small"
        icon={<DoubleLeftOutlined />}
        disabled={!hasPrev}
        onClick={() => goTo(1)}
        title="首页"
      />
      <Button
        size="small"
        icon={<LeftOutlined />}
        disabled={!hasPrev}
        onClick={() => goTo(safeCurrent - 1)}
        title="上一页"
      >
        上一页
      </Button>

      {buildPageItems(totalPages, safeCurrent).map((item, index) =>
        typeof item === 'number' ? (
          <Button
            key={item}
            size="small"
            type={item === safeCurrent ? 'primary' : 'default'}
            onClick={() => goTo(item)}
            title={`第 ${item} 页`}
          >
            {item}
          </Button>
        ) : (
          <Text
            key={`${item}-${index}`}
            type="secondary"
            style={{ padding: '0 2px', userSelect: 'none' }}
          >
            •••
          </Text>
        )
      )}

      <Button
        size="small"
        disabled={!hasNext}
        onClick={() => goTo(safeCurrent + 1)}
        title="下一页"
      >
        下一页 <RightOutlined />
      </Button>
      <Button
        size="small"
        icon={<DoubleRightOutlined />}
        disabled={!hasNext}
        onClick={() => goTo(totalPages)}
        title="末页"
      />

      {showQuickJumper && (
        <>
          <Text type="secondary" style={{ marginLeft: 8 }}>
            跳至
          </Text>
          <InputNumber
            size="small"
            style={{ width: 64 }}
            min={1}
            max={totalPages}
            precision={0}
            value={jumpValue}
            onChange={(value) => setJumpValue(value)}
            onPressEnter={handleJump}
          />
          <Text type="secondary">页</Text>
          <Button size="small" type="primary" ghost onClick={handleJump}>
            跳转
          </Button>
        </>
      )}
    </div>
  );
};

export default TablePagination;
