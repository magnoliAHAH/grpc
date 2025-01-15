package auth

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sso/internal/domain/models"
	"sso/internal/lib/jwt"
	"sso/internal/services/storage"
	"time"

	"golang.org/x/crypto/bcrypt"
)

type Auth struct {
	log         *slog.Logger
	usrSaver    UserSaver
	usrProvider UserProvider
	appProvider AppProvider
	tokenTTL    time.Duration
}

type UserSaver interface {
	SaveUser(
		ctx context.Context,
		email string,
		passHash []byte,
	) (uid int64, err error)
}
type UserProvider interface {
	User(ctx context.Context, email string) (models.User, error)
	IsAdmin(ctx context.Context, userID int64) (bool, error)
}

type AppProvider interface {
	App(ctx context.Context, appID int) (models.App, error)
}

var (
	ErrInbalidCredentials = errors.New("invalid credentials")
	ErrInbalidAppID       = errors.New("invalid app id")
	ErrUserExists         = errors.New("invalid app id")
)

// New возвращает новый экземляр Auth. (constructor function)
func New(
	log *slog.Logger,
	userSaver UserSaver,
	userProvider UserProvider,
	appProvider AppProvider,
	tokenTTL time.Duration,
) *Auth {
	return &Auth{
		usrSaver:    userSaver,
		usrProvider: userProvider,
		log:         log,
		appProvider: appProvider,
		tokenTTL:    tokenTTL,
	}
}

// Login проверяет есть ли такой пользователь в системе.
//
// Если пользователь есть, но пароль неверный - ошибка.
// Если пользователя не существует - ошибка.
func (a *Auth) Login(
	ctx context.Context,
	email string,
	password string,
	appID int,
) (string, error) {
	const op = "auth.RegisterNewUser"
	log := a.log.With(

		slog.String("op", op),
		// логгирование почты с возможностью удалять по апросу или не ранить
		slog.String("email", email),
	)
	log.Info("attempting to login user")

	user, err := a.usrProvider.User(ctx, email)
	if err != nil {
		if errors.Is(err, storage.ErrUserNotFound) {
			a.log.Warn("user not found", slog.String("error", err.Error()))
			return "", fmt.Errorf("%s: %w", op, ErrInbalidCredentials)
		}
	}

	if err := bcrypt.CompareHashAndPassword(user.PassHash, []byte(password)); err != nil {
		a.log.Info("invalid credentials", slog.String("error", err.Error()))

		return "", fmt.Errorf("%s: %w", op, ErrInbalidCredentials)
	}

	app, err := a.appProvider.App(ctx, appID)
	if err != nil {
		return "", fmt.Errorf("%s: %w", op, err)
	}

	log.Info("user logged is successfully")

	token, err := jwt.NewToken(user, app, a.tokenTTL)
	if err != nil {
		a.log.Error("failed to generate token", slog.String("error", err.Error()))

		return "", fmt.Errorf("%s: %w", op, ErrInbalidCredentials)
	}
	return token, nil
}

// RegisterNewUser регистрирует нового пользователя в системе и возвращает userID.
// Если пользователь с таким username существует - ошибка
func (a *Auth) RegisterNewUser(
	ctx context.Context,
	email string,
	pass string,
) (int64, error) {
	const op = "auth.RegisterNewUser"

	log := a.log.With(
		slog.String("op", op),
		// логгирование почты с возможностью удалять по апросу или не ранить
		slog.String("email", email),
	)

	log.Info("registering user")

	passHash, err := bcrypt.GenerateFromPassword([]byte(pass), bcrypt.DefaultCost)

	if err != nil {
		log.Error("failed to generate password hash", slog.String("error", err.Error()))
		return 0, fmt.Errorf("%s: %w", op, err)
	}

	id, err := a.usrSaver.SaveUser(ctx, email, passHash)
	if err != nil {

		if errors.Is(err, storage.ErrUserExists) {
			log.Warn("user already exists", slog.String("error", err.Error()))
			return 0, fmt.Errorf("%s: %w", op, ErrUserExists)
		}

		log.Error("failed to save user", slog.String("error", err.Error()))
		return 0, fmt.Errorf("%s: %w", op, err)
	}
	log.Info("user registered")
	return id, nil
}

// IsAdmin проверяет является ли пользователь администратором
func (a *Auth) IsAdmin(
	ctx context.Context,
	userID int64,
) (bool, error) {
	const op = "Auth.IsAdmin"

	log := a.log.With(
		slog.String("op", op),
		slog.Int64("user_id", userID),
	)
	log.Info("checking if user is admin")

	isAdmin, err := a.usrProvider.IsAdmin(ctx, userID)
	if err != nil {
		if errors.Is(err, storage.ErrAppNotFound) {
			log.Warn("user not found", slog.String("error", err.Error()))
		}
		return false, fmt.Errorf("%s: %w", op, ErrInbalidAppID)
	}

	log.Info("checked if user is admin", slog.Bool("is_admin", isAdmin))

	return isAdmin, nil
}
