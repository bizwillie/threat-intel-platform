# UTIP Frontend

Angular-based frontend for the Unified Threat Intelligence Platform (UTIP).

## Features

- **MITRE ATT&CK Visualization**: Interactive matrix display
- **Threat Actor Attribution**: Real-time attribution analysis
- **Remediation Guidance**: Actionable defense recommendations
- **Layer Management**: Create and manage ATT&CK layers from intel + vulns
- **Midnight Vulture Theme**: Custom dark theme with glassmorphism

## Development

```bash
# Install dependencies
npm install

# Start development server
npm start

# Build for production
npm run build:prod
```

## Docker

```bash
# Build container
docker build -t utip-frontend .

# Run container
docker run -p 4200:80 utip-frontend
```

## Architecture

- **Framework**: Angular 17 (Standalone Components)
- **HTTP**: HttpClient with JWT authentication
- **Styling**: SCSS with CSS custom properties
- **Icons**: Lucide Angular
- **Fonts**: Inter (UI), JetBrains Mono (Code)

## Environment Configuration

Edit `src/environments/environment.ts` for development settings:
- `apiUrl`: Core API backend URL
- `keycloakUrl`: Keycloak authentication URL
- `keycloakRealm`: Keycloak realm name
- `keycloakClientId`: OAuth client ID

## API Integration

All API communication is handled through `ApiService`:
- Layer operations (generate, load, delete)
- Threat intel uploads
- Vulnerability scan uploads
- Attribution analysis
- Remediation guidance

## Theme: Midnight Vulture

**Classification**: INTERNAL USE ONLY

Color coding:
- **Red (#EF4444)**: Critical overlap (intel + vulnerability)
- **Yellow (#F59E0B)**: Intel only
- **Blue (#3B82F6)**: Vulnerability only
