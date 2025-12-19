'use client'

import { useRef, useEffect } from 'react'
import Editor, { OnMount, OnChange } from '@monaco-editor/react'
import type { editor } from 'monaco-editor'

interface CodeEditorProps {
  value: string
  onChange: (value: string) => void
  language?: string
  readOnly?: boolean
  highlightLines?: number[]
  height?: string
}

// Solidity language configuration
const solidityLanguageConfig = {
  keywords: [
    'pragma', 'solidity', 'contract', 'interface', 'library', 'abstract',
    'function', 'modifier', 'event', 'struct', 'enum', 'mapping',
    'public', 'private', 'internal', 'external', 'pure', 'view', 'payable',
    'memory', 'storage', 'calldata', 'returns', 'return',
    'if', 'else', 'for', 'while', 'do', 'break', 'continue',
    'true', 'false', 'new', 'delete', 'this', 'super',
    'require', 'assert', 'revert', 'emit',
    'constructor', 'fallback', 'receive',
    'virtual', 'override', 'immutable', 'constant',
    'import', 'from', 'as', 'is', 'using',
    'try', 'catch', 'unchecked',
  ],
  typeKeywords: [
    'address', 'bool', 'string', 'bytes', 'byte',
    'int', 'int8', 'int16', 'int32', 'int64', 'int128', 'int256',
    'uint', 'uint8', 'uint16', 'uint32', 'uint64', 'uint128', 'uint256',
    'bytes1', 'bytes2', 'bytes4', 'bytes8', 'bytes16', 'bytes32',
    'fixed', 'ufixed',
  ],
  operators: [
    '=', '>', '<', '!', '~', '?', ':', '==', '<=', '>=', '!=',
    '&&', '||', '++', '--', '+', '-', '*', '/', '&', '|', '^', '%',
    '<<', '>>', '+=', '-=', '*=', '/=', '&=', '|=', '^=',
    '%=', '<<=', '>>=', '=>',
  ],
}

export default function CodeEditor({
  value,
  onChange,
  readOnly = false,
  highlightLines = [],
  height = '500px',
}: CodeEditorProps) {
  const editorRef = useRef<editor.IStandaloneCodeEditor | null>(null)
  const decorationsRef = useRef<string[]>([])

  const handleEditorDidMount: OnMount = (editor, monaco) => {
    editorRef.current = editor

    // Register Solidity language if not exists
    if (!monaco.languages.getLanguages().some((lang: { id: string }) => lang.id === 'sol')) {
      monaco.languages.register({ id: 'sol' })
      
      monaco.languages.setMonarchTokensProvider('sol', {
        keywords: solidityLanguageConfig.keywords,
        typeKeywords: solidityLanguageConfig.typeKeywords,
        operators: solidityLanguageConfig.operators,
        symbols: /[=><!~?:&|+\-*\/\^%]+/,
        
        tokenizer: {
          root: [
            [/[a-zA-Z_]\w*/, {
              cases: {
                '@keywords': 'keyword',
                '@typeKeywords': 'type',
                '@default': 'identifier'
              }
            }],
            [/[{}()\[\]]/, '@brackets'],
            [/[<>](?!@symbols)/, '@brackets'],
            [/@symbols/, {
              cases: {
                '@operators': 'operator',
                '@default': ''
              }
            }],
            [/\d*\.\d+([eE][\-+]?\d+)?/, 'number.float'],
            [/0[xX][0-9a-fA-F]+/, 'number.hex'],
            [/\d+/, 'number'],
            [/[;,.]/, 'delimiter'],
            [/"([^"\\]|\\.)*$/, 'string.invalid'],
            [/"/, { token: 'string.quote', bracket: '@open', next: '@string' }],
            [/'[^\\']'/, 'string'],
            [/'/, 'string.invalid'],
            [/\/\/.*$/, 'comment'],
            [/\/\*/, 'comment', '@comment'],
          ],
          string: [
            [/[^\\"]+/, 'string'],
            [/\\./, 'string.escape'],
            [/"/, { token: 'string.quote', bracket: '@close', next: '@pop' }]
          ],
          comment: [
            [/[^\/*]+/, 'comment'],
            [/\*\//, 'comment', '@pop'],
            [/[\/*]/, 'comment']
          ],
        },
      })
    }

    // Define custom theme
    monaco.editor.defineTheme('vanguard-dark', {
      base: 'vs-dark',
      inherit: true,
      rules: [
        { token: 'keyword', foreground: '22c55e', fontStyle: 'bold' },
        { token: 'type', foreground: '06b6d4' },
        { token: 'identifier', foreground: 'e4e4e7' },
        { token: 'number', foreground: 'f59e0b' },
        { token: 'number.hex', foreground: 'f59e0b' },
        { token: 'number.float', foreground: 'f59e0b' },
        { token: 'string', foreground: 'a855f7' },
        { token: 'comment', foreground: '6b7280', fontStyle: 'italic' },
        { token: 'operator', foreground: '22c55e' },
        { token: 'delimiter', foreground: '71717a' },
      ],
      colors: {
        'editor.background': '#111113',
        'editor.foreground': '#e4e4e7',
        'editor.lineHighlightBackground': '#1c1c1f',
        'editor.selectionBackground': '#22c55e33',
        'editorCursor.foreground': '#22c55e',
        'editorLineNumber.foreground': '#52525b',
        'editorLineNumber.activeForeground': '#22c55e',
        'editor.selectionHighlightBackground': '#22c55e22',
        'editorGutter.background': '#0a0a0b',
        'editorWidget.background': '#18181b',
        'editorWidget.border': '#27272a',
      },
    })

    monaco.editor.setTheme('vanguard-dark')
  }

  const handleChange: OnChange = (value) => {
    onChange(value || '')
  }

  // Update line decorations when highlightLines changes
  useEffect(() => {
    if (editorRef.current && highlightLines.length > 0) {
      const decorations = highlightLines.map(line => ({
        range: {
          startLineNumber: line,
          startColumn: 1,
          endLineNumber: line,
          endColumn: 1,
        },
        options: {
          isWholeLine: true,
          className: 'finding-highlight',
          glyphMarginClassName: 'finding-glyph',
          linesDecorationsClassName: 'finding-line-decoration',
        },
      }))

      decorationsRef.current = editorRef.current.deltaDecorations(
        decorationsRef.current,
        decorations
      )
    }
  }, [highlightLines])

  return (
    <div className="rounded-lg overflow-hidden border border-border/50">
      <Editor
        height={height}
        defaultLanguage="sol"
        value={value}
        onChange={handleChange}
        onMount={handleEditorDidMount}
        options={{
          readOnly,
          minimap: { enabled: false },
          fontSize: 14,
          fontFamily: "'JetBrains Mono', 'Fira Code', monospace",
          lineNumbers: 'on',
          scrollBeyondLastLine: false,
          automaticLayout: true,
          tabSize: 4,
          wordWrap: 'on',
          padding: { top: 16, bottom: 16 },
          renderLineHighlight: 'all',
          cursorBlinking: 'smooth',
          cursorSmoothCaretAnimation: 'on',
          smoothScrolling: true,
          glyphMargin: true,
          folding: true,
          lineDecorationsWidth: 10,
        }}
        loading={
          <div className="flex items-center justify-center h-full bg-card">
            <div className="text-muted-foreground font-mono text-sm">
              Loading editor...
            </div>
          </div>
        }
      />
    </div>
  )
}