import React, { useMemo } from 'react';

interface DiffViewerProps {
  /** Unified diff content (from `difflib.unified_diff` or `git diff`). */
  diff: string;
  /** Optional max height; defaults to 400px. */
  maxHeight?: number;
}

interface DiffLine {
  type: 'context' | 'add' | 'remove' | 'header' | 'hunk';
  content: string;
  oldLine?: number;
  newLine?: number;
}

/** Parse unified diff text into structured lines for rendering. */
function parseDiff(diffText: string): DiffLine[] {
  const lines = diffText.split('\n');
  let oldLine = 0;
  let newLine = 0;

  return lines.map((line) => {
    // Diff header lines (--- / +++ / diff --git)
    if (line.startsWith('---') || line.startsWith('+++') || line.startsWith('diff ')) {
      return { type: 'header', content: line };
    }

    // Hunk header (@@ -1,5 +1,6 @@)
    const hunkMatch = line.match(/^@@ -(\d+),?\d* \+(\d+),?\d* @@/);
    if (hunkMatch) {
      oldLine = parseInt(hunkMatch[1], 10);
      newLine = parseInt(hunkMatch[2], 10);
      return { type: 'hunk', content: line };
    }

    // Added line
    if (line.startsWith('+')) {
      return {
        type: 'add',
        content: line.substring(1),
        newLine: newLine++,
      };
    }

    // Removed line
    if (line.startsWith('-')) {
      return {
        type: 'remove',
        content: line.substring(1),
        oldLine: oldLine++,
      };
    }

    // Context line (starts with space or empty)
    const content = line.startsWith(' ') ? line.substring(1) : line;
    return {
      type: 'context',
      content,
      oldLine: oldLine++,
      newLine: newLine++,
    };
  });
}

const LINE_STYLES: Record<string, React.CSSProperties> = {
  header: {
    background: '#f0f3f6',
    color: '#57606a',
    fontWeight: 600,
  },
  hunk: {
    background: '#ddf4ff',
    color: '#0969da',
    fontWeight: 600,
  },
  add: {
    background: '#dafbe1',
    color: '#1a7f37',
  },
  remove: {
    background: '#ffebe9',
    color: '#cf222e',
  },
  context: {
    background: '#f6f8fa',
    color: '#57606a',
  },
};

const PREFIX: Record<string, string> = {
  add: '+',
  remove: '-',
  context: ' ',
  header: '',
  hunk: '',
};

/** Unified diff viewer with syntax-highlighted line rendering. */
const DiffViewer: React.FC<DiffViewerProps> = ({ diff, maxHeight = 400 }) => {
  const parsedLines = useMemo(() => parseDiff(diff), [diff]);

  if (!diff || diff.trim().length === 0) {
    return (
      <div
        style={{
          padding: '12px 16px',
          color: '#999',
          fontSize: '12px',
          background: '#f6f8fa',
          borderRadius: 4,
        }}
      >
        无差异内容
      </div>
    );
  }

  return (
    <div
      style={{
        background: '#f6f8fa',
        borderRadius: 6,
        border: '1px solid #d0d7de',
        overflow: 'auto',
        maxHeight,
        fontSize: '12px',
        fontFamily:
          "'SFMono-Regular', Consolas, 'Liberation Mono', Menlo, monospace",
        lineHeight: '1.6',
      }}
    >
      <table style={{ borderCollapse: 'collapse', width: '100%' }}>
        <tbody>
          {parsedLines.map((line, idx) => {
            const style = LINE_STYLES[line.type] || LINE_STYLES.context;
            const prefix = PREFIX[line.type] || '';
            const showLineNum = line.type === 'add' || line.type === 'context';
            const oldNum = line.type === 'remove' || line.type === 'context';

            return (
              <tr key={idx} style={style}>
                {/* Old line number */}
                <td
                  style={{
                    width: '40px',
                    textAlign: 'right',
                    padding: '0 6px',
                    color: '#8c959f',
                    userSelect: 'none',
                    whiteSpace: 'nowrap',
                    borderRight: '1px solid #d0d7de',
                  }}
                >
                  {oldNum && line.oldLine !== undefined ? line.oldLine : ''}
                </td>
                {/* New line number */}
                <td
                  style={{
                    width: '40px',
                    textAlign: 'right',
                    padding: '0 6px',
                    color: '#8c959f',
                    userSelect: 'none',
                    whiteSpace: 'nowrap',
                    borderRight: '1px solid #d0d7de',
                  }}
                >
                  {showLineNum && line.newLine !== undefined
                    ? line.newLine
                    : ''}
                </td>
                {/* Prefix */}
                <td
                  style={{
                    width: '16px',
                    textAlign: 'center',
                    padding: '0 2px',
                    userSelect: 'none',
                    fontWeight: 600,
                  }}
                >
                  {prefix}
                </td>
                {/* Content */}
                <td
                  style={{
                    padding: '0 8px',
                    whiteSpace: 'pre-wrap',
                    wordBreak: 'break-all',
                  }}
                >
                  {line.content || '\u00a0'}
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
};

export default DiffViewer;
