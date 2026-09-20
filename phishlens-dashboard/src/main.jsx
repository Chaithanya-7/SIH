import React from 'react'
import ReactDOM from 'react-dom/client'
import App from './App.jsx'
// Tokens load before component styles so theme overrides resolve predictably.
import './styles/theme.css'
import './style.css'

ReactDOM.createRoot(document.getElementById('root')).render(
  <React.StrictMode>
    <App />
  </React.StrictMode>,
)
