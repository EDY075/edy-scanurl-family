import React from 'react';
import ReactDOM from 'react-dom/client';
import { registerSW } from 'virtual:pwa-register';
import { FamilyApp } from './family/FamilyApp';
import { nativeFamily } from './family/family-native';

const root = document.getElementById('root');
if (!root) throw new Error('Application root was not found.');

if (!nativeFamily) registerSW({ immediate: true });
ReactDOM.createRoot(root).render(<React.StrictMode><FamilyApp /></React.StrictMode>);
