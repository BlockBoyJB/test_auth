compose-up:
	docker-compose up -d --build

compose-down:
	docker-compose down

run:
	go run cmd/app/main.go

docs:
	swag init -g internal/app/app.go --pd
.PHONY: docs

mocks:
	mockgen -source=internal/repo/repo.go -destination=internal/mocks/repomocks/repo.go -package=repomocks
	mockgen -source=internal/token/token.go -destination=internal/mocks/tokenmocks/token.go -package=tokenmocks
	mockgen -source=internal/service/service.go -destination=internal/mocks/servicemocks/service.go -package=servicemocks
	mockgen -source=internal/webhook/webhook.go -destination=internal/mocks/webhookmocks/webhook.go -package=webhookmocks

pg-tests:
	docker run --name postgres --rm -d \
		-p 6000:6000 \
		-e POSTGRES_USER=postgres \
		-e POSTGRES_PASSWORD=1234567890 \
		-e POSTGRES_DB=postgres postgres:15 -p 6000

init-test-containers: pg-tests

stop-test-containers:
	docker stop postgres

init-tests:
	go test -v ./...

tests: init-test-containers init-tests stop-test-containers
