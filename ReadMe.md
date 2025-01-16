##Для работы
#Миграция для работы
task migrate

##Для тестов
#Миграция базы для тестов
go run .\cmd\migrator\main.go --storage-path=./storage/sso.db --migrations-path=./tests/migrations --migration-table=migrations_test
