.PHONY: dev prod down logs dev-down prod-down clean build test

# Development environment
dev:
	docker-compose -f docker-compose.dev.yml up --build

# Production environment
prod:
	docker-compose -f docker-compose.prod.yml --env-file .env.prod up -d

# Stop all environments
down:
	docker-compose -f docker-compose.dev.yml down || docker-compose -f docker-compose.prod.yml down

# Follow logs
logs:
	docker-compose -f docker-compose.dev.yml logs -f || docker-compose -f docker-compose.prod.yml logs -f

# Stop development only
dev-down:
	docker-compose -f docker-compose.dev.yml down

# Stop production only
prod-down:
	docker-compose -f docker-compose.prod.yml down

# Clean up all containers, volumes, and images
clean:
	docker-compose -f docker-compose.dev.yml down -v --rmi all
	docker-compose -f docker-compose.prod.yml down -v --rmi all
	docker system prune -f

# Build application without starting
build:
	docker-compose -f docker-compose.dev.yml build

# Run tests
test:
	go test ./...

# Show status of containers
status:
	docker-compose -f docker-compose.dev.yml ps || docker-compose -f docker-compose.prod.yml ps

# Shell into app container
shell:
	docker-compose -f docker-compose.dev.yml exec app sh

# View specific service logs
logs-app:
	docker-compose -f docker-compose.dev.yml logs -f app

logs-db:
	docker-compose -f docker-compose.dev.yml logs -f redis scylla1

logs-kafka:
	docker-compose -f docker-compose.dev.yml logs -f kafka zookeeper

logs-elastic:
	docker-compose -f docker-compose.dev.yml logs -f elasticsearch kibana

# Restart services
restart:
	docker-compose -f docker-compose.dev.yml restart

# Database operations
db-shell:
	docker-compose -f docker-compose.dev.yml exec scylla1 cqlsh -u cassandra

redis-cli:
	docker-compose -f docker-compose.dev.yml exec redis redis-cli

# Help
help:
	@echo "Available commands:"
	@echo "  make dev       - Start development environment"
	@echo "  make prod      - Start production environment"
	@echo "  make down      - Stop all environments"
	@echo "  make logs      - Follow logs from all services"
	@echo "  make clean     - Clean up everything"
	@echo "  make build     - Build containers without starting"
	@echo "  make test      - Run Go tests"
	@echo "  make status    - Show container status"
	@echo "  make shell     - Shell into app container"
	@echo "  make restart   - Restart development services"