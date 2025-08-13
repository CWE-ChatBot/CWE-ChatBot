# REST API Spec

This section defines the core REST API endpoints exposed by the Chatbot Application (Chainlit Backend) for internal UI communication and essential system functions in the MVP. A more extensive programmatic API for external clients is a post-MVP consideration as per NFR37.

## OpenAPI 3.0 Specification (YAML)

```yaml
openapi: 3.0.0
info:
  title: CWE ChatBot Internal Configuration API (MVP)
  version: 1.0.0
  description: Minimal API for managing user-specific chatbot configurations and health status, primarily used by the internal UI.
servers:
  - url: /api
    description: Relative path from Chainlit application base URL
tags:
  - name: Health
    description: API Health Check
  - name: User Configuration
    description: Operations related to user-specific chatbot settings
paths:
  /health:
    get:
      tags:
        - Health
      summary: Health check endpoint
      operationId: getHealthStatus
      responses:
        '200':
          description: Service is healthy
          content:
            application/json:
              schema:
                type: object
                properties:
                  status:
                    type: string
                    example: "healthy"
  /user/config:
    get:
      tags:
        - User Configuration
      summary: Retrieve authenticated user's chatbot configuration
      operationId: getUserConfig
      security:
        - bearerAuth: []
      responses:
        '200':
          description: User configuration retrieved successfully
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/UserConfig'
        '401':
          description: Unauthorized
    put:
      tags:
        - User Configuration
      summary: Update authenticated user's chatbot configuration
      operationId: updateUserConfig
      security:
        - bearerAuth: []
      requestBody:
        required: true
        content:
          application/json:
            schema:
              $ref: '#/components/schemas/UserConfigUpdate'
      responses:
        '200':
          description: Configuration updated successfully
        '400':
          description: Invalid input
        '401':
          description: Unauthorized
components:
  securitySchemes:
    bearerAuth:
      type: http
      scheme: bearer
      bearerFormat: JWT # JWTs issued via OAuth provider authentication
  schemas:
    UserConfig:
      type: object
      description: Represents the user-configurable settings for the chatbot.
      properties:
        role:
          type: string
          enum: [ "PSIRT Member", "Developer", "Academic Researcher", "Bug Bounty Hunter", "Product Manager", "Admin" ]
          description: The user's selected role, influencing chatbot responses (FR4).
        preferences:
          type: object
          description: User-specific UI or interaction preferences.
          additionalProperties: true
        llmModelConfig:
          type: object
          description: Configuration for Bring Your Own LLM model (FR29).
          properties:
            type:
              type: string
              enum: [ "api", "self-hosted" ]
              description: Type of LLM integration (API endpoint or self-hosted).
            endpoint:
              type: string
              format: uri
              description: Endpoint URL for BYO LLM API or self-hosted model.
            modelName:
              type: string
              description: Name or identifier of the BYO LLM.
          required:
            - type
            - endpoint
            - modelName
      required:
        - role # Role is likely a mandatory user setting
      example:
        role: "Developer"
        preferences:
          theme: "dark"
          verbosity: "verbose"
        llmModelConfig:
          type: "api"
          endpoint: "https://api.example.com/custom-llm"
          modelName: "custom-model-v2"
    UserConfigUpdate:
      type: object
      description: Schema for updating user-configurable chatbot settings.
      properties:
        role:
          type: string
          enum: [ "PSIRT Member", "Developer", "Academic Researcher", "Bug Bounty Hunter", "Product Manager", "Admin" ]
        preferences:
          type: object
        llmModelConfig:
          type: object
          properties:
            type:
              type: string
              enum: [ "api", "self-hosted" ]
            endpoint:
              type: string
              format: uri
            modelName:
              type: string
          required:
            - type
            - endpoint
            - modelName
      example:
        role: "PSIRT Member"
        preferences:
          notifications: "email"
        llmModelConfig:
          type: "self-hosted"
          endpoint: "http://my-llm-server.internal/model"
          modelName: "local-llama"
```
