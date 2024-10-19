# Build app
FROM public.ecr.aws/docker/library/golang:1.23.2-alpine3.20 AS build

WORKDIR /src/bin

# Add build argument
ARG INCLUDE_RIE=false

# Conditionally download aws-lambda-rie, useful for local development
RUN if [ "$INCLUDE_RIE" = "true" ]; then \
    wget -O aws-lambda-rie "https://github.com/aws/aws-lambda-runtime-interface-emulator/releases/latest/download/aws-lambda-rie" && \
    chmod +x aws-lambda-rie; \
    fi

WORKDIR /src

# Copy the Go modules files
COPY go.mod go.sum ./

# Download dependencies
RUN go mod download

# Copy the source code
COPY cmd/ ./cmd/
COPY pkg/ ./pkg/
COPY internal/ ./internal/

# Verify and build
RUN go mod verify
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -tags lambda.norpc -o bin/lambda cmd/lambda/main.go

# Copy app to new image
FROM public.ecr.aws/docker/library/alpine:3.20 AS app

WORKDIR /app

# Copy the compiled application
COPY --from=build /src/bin/ .

ENTRYPOINT ["/app/lambda"]
