import { Editor  } from '@monaco-editor/react'
import editorTheme from 'monaco-themes/themes/Tomorrow-Night-Bright.json'

function MonacoEditor({ 
  value, 
  onChange, 
  language = 'yaml', 
  placeholder = '',
  height = '300px',
  disabled = false 
}) {
  const handleEditorChange = (value) => {
    onChange(value || '')
  }

  const editorOptions = {
    minimap: { enabled: false },
    scrollBeyondLastLine: false,
    fontSize: 13,
    fontFamily: '"SF Mono", "Monaco", "Inconsolata", "Roboto Mono", "Source Code Pro", monospace',
    lineNumbers: 'on',
    glyphMargin: false,
    folding: true,
    lineDecorationsWidth: 0,
    lineNumbersMinChars: 3,
    renderLineHighlight: 'line',
    scrollbar: {
      vertical: 'visible',
      horizontal: 'visible',
      useShadows: false,
      verticalHasArrows: false,
      horizontalHasArrows: false,
      verticalScrollbarSize: 8,
      horizontalScrollbarSize: 8
    },
    readOnly: disabled,
    automaticLayout: true,
    wordWrap: 'on',
    wrappingIndent: 'indent',
    tabSize: 2,
    insertSpaces: true
  }

  const handleEditorDidMount = (monaco) => {
    monaco.editor.defineTheme('Tomorrow-Night-Bright', {
      base: 'vs-dark',
      inherit: true,
      ...editorTheme
    });
  };
  console.log(editorTheme)

  return (
    <div style={{ height, border: '1px solid #3e3e42', borderRadius: '4px', overflow: 'hidden' }}>
      <Editor
        height={height}
        language={language}
        value={value}
        onChange={handleEditorChange}
        beforeMount={handleEditorDidMount}
        theme="Tomorrow-Night-Bright"
        options={editorOptions}
        loading={<div style={{ padding: '16px', color: '#969696' }}>Loading editor...</div>}
      />
    </div>
  )
}

export default MonacoEditor