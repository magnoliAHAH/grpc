# Установка
go mod tidy

## Windows
npm install -g @go-task/cli\
set CGO_ENABLED=1\
mkdir storage\
task migrate

# Миграция базы для тестов
go run .\cmd\migrator\main.go --storage-path=./storage/sso.db --migrations-path=./tests/migrations --migration-table=migrations_test

# Запуск
go run .\cmd\sso\ --config=./config/local.yaml
