import '@testing-library/jest-dom'
import { afterEach } from 'vitest'

afterEach(() => {
  delete window.__AGENT_BOM_CONFIG__
})
