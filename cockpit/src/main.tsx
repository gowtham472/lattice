import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';
import { App } from './App';
// the site's text and code faces, bundled: the cockpit is served offline
import '@fontsource-variable/plus-jakarta-sans';
import '@fontsource-variable/jetbrains-mono';
import './styles.css';

const root = document.getElementById('root');
if (!root) throw new Error('missing #root');

createRoot(root).render(
  <StrictMode>
    <App />
  </StrictMode>,
);
