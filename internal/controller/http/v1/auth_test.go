package v1

import (
	"bytes"
	"context"
	"errors"
	"github.com/golang/mock/gomock"
	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/assert"
	"net/http"
	"net/http/httptest"
	"test_auth/internal/mocks/servicemocks"
	"test_auth/internal/service"
	"test_auth/pkg/validator"
	"testing"
)

func TestAuthRouter_signIn(t *testing.T) {
	type args struct {
		ctx   context.Context
		input service.TokenInput
	}

	type mockBehaviour func(m *servicemocks.MockAuth, a args)

	testCases := []struct {
		testName      string
		args          args
		mockBehaviour mockBehaviour
		inputBody     string
		expectCode    int
		expectBody    string
	}{
		{
			testName: "correct test",
			args: args{
				ctx: context.Background(),
				input: service.TokenInput{
					UserId:    "VASYA",
					UserAgent: "GOOGLE",
					IP:        "127.0.0.1",
				},
			},
			mockBehaviour: func(m *servicemocks.MockAuth, a args) {
				m.EXPECT().SignIn(a.ctx, a.input).Return(service.TokenOutput{
					Access:  "ACCESS",
					Refresh: "REFRESH",
				}, nil)
			},
			inputBody:  `{"id": "VASYA"}`,
			expectCode: http.StatusOK,
			expectBody: `{"access":"ACCESS","refresh":"REFRESH"}` + "\n",
		},
		{
			testName:      "id field is incorrect",
			mockBehaviour: func(m *servicemocks.MockAuth, a args) {},
			inputBody:     `{"id": 1}`,
			expectCode:    http.StatusBadRequest,
		},
		{
			testName:      "id field is missed",
			mockBehaviour: func(m *servicemocks.MockAuth, a args) {},
			inputBody:     `{"foobar": "foobar"}`,
			expectCode:    http.StatusBadRequest,
		},
		{
			testName: "signIn error",
			args: args{
				ctx: context.Background(),
				input: service.TokenInput{
					UserId:    "VASYA",
					UserAgent: "GOOGLE",
					IP:        "127.0.0.1",
				},
			},
			mockBehaviour: func(m *servicemocks.MockAuth, a args) {
				m.EXPECT().SignIn(a.ctx, a.input).Return(service.TokenOutput{}, errors.New("some error"))
			},
			inputBody:  `{"id": "VASYA"}`,
			expectCode: http.StatusInternalServerError,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.testName, func(t *testing.T) {
			ctrl := gomock.NewController(t)

			auth := servicemocks.NewMockAuth(ctrl)
			tc.mockBehaviour(auth, tc.args)

			e := echo.New()
			e.Validator = validator.NewValidator()
			NewRouter(e, &service.Services{Auth: auth})

			w := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/sign-in", bytes.NewBufferString(tc.inputBody))
			req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
			req.Header.Set("User-Agent", tc.args.input.UserAgent)
			req.Header.Set(echo.HeaderXRealIP, tc.args.input.IP)

			e.ServeHTTP(w, req)

			assert.Equal(t, tc.expectCode, w.Code)
			assert.Equal(t, tc.expectBody, w.Body.String())
		})
	}
}

func TestAuthRouter_refresh(t *testing.T) {
	type args struct {
		ctx   context.Context
		input service.RefreshInput
	}

	type mockBehaviour func(m *servicemocks.MockAuth, a args)

	testCases := []struct {
		testName      string
		args          args
		mockBehaviour mockBehaviour
		inputBody     string
		expectCode    int
		expectBody    string
	}{
		{
			testName: "correct test",
			args: args{
				ctx: context.Background(),
				input: service.RefreshInput{
					Access:    "ACCESS",
					Refresh:   "REFRESH",
					UserAgent: "GOOGLE",
					IP:        "127.0.0.1",
				},
			},
			mockBehaviour: func(m *servicemocks.MockAuth, a args) {
				m.EXPECT().Refresh(a.ctx, a.input).Return(service.TokenOutput{
					Access:  "NEW_ACCESS",
					Refresh: "NEW_REFRESH",
				}, nil)
			},
			inputBody:  `{"access": "ACCESS", "refresh": "REFRESH"}`,
			expectCode: http.StatusOK,
			expectBody: `{"access":"NEW_ACCESS","refresh":"NEW_REFRESH"}` + "\n",
		},
		{
			testName:      "field access is invalid",
			mockBehaviour: func(m *servicemocks.MockAuth, a args) {},
			inputBody:     `{"access": 1, "refresh": "REFRESH"}`,
			expectCode:    http.StatusBadRequest,
		},
		{
			testName:      "field refresh is invalid",
			mockBehaviour: func(m *servicemocks.MockAuth, a args) {},
			inputBody:     `{"access": 1, "refresh": "REFRESH"}`,
			expectCode:    http.StatusBadRequest,
		},
		{
			testName:      "field access is missed",
			mockBehaviour: func(m *servicemocks.MockAuth, a args) {},
			inputBody:     `{"refresh": "REFRESH"}`,
			expectCode:    http.StatusBadRequest,
		},
		{
			testName:      "field refresh is missed",
			mockBehaviour: func(m *servicemocks.MockAuth, a args) {},
			inputBody:     `{"access": "ACCESS"}`,
			expectCode:    http.StatusBadRequest,
		},
		{
			testName: "invalid token",
			args: args{
				ctx: context.Background(),
				input: service.RefreshInput{
					Access:    "INVALID_ACCESS",
					Refresh:   "INVALID_REFRESH",
					UserAgent: "GOOGLE",
					IP:        "127.0.0.1",
				},
			},
			mockBehaviour: func(m *servicemocks.MockAuth, a args) {
				m.EXPECT().Refresh(a.ctx, a.input).Return(service.TokenOutput{}, service.ErrInvalidToken)
			},
			inputBody:  `{"access": "INVALID_ACCESS", "refresh": "INVALID_REFRESH"}`,
			expectCode: http.StatusForbidden,
		},
		{
			testName: "unexpected error",
			args: args{
				ctx: context.Background(),
				input: service.RefreshInput{
					Access:    "ACCESS",
					Refresh:   "REFRESH",
					UserAgent: "GOOGLE",
					IP:        "127.0.0.1",
				},
			},
			mockBehaviour: func(m *servicemocks.MockAuth, a args) {
				m.EXPECT().Refresh(a.ctx, a.input).Return(service.TokenOutput{}, errors.New("some error"))
			},
			inputBody:  `{"access": "ACCESS", "refresh": "REFRESH"}`,
			expectCode: http.StatusInternalServerError,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.testName, func(t *testing.T) {
			ctrl := gomock.NewController(t)

			auth := servicemocks.NewMockAuth(ctrl)
			tc.mockBehaviour(auth, tc.args)

			e := echo.New()
			e.Validator = validator.NewValidator()
			NewRouter(e, &service.Services{Auth: auth})

			w := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/refresh", bytes.NewBufferString(tc.inputBody))
			req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
			req.Header.Set("User-Agent", tc.args.input.UserAgent)
			req.Header.Set(echo.HeaderXRealIP, tc.args.input.IP)

			e.ServeHTTP(w, req)

			assert.Equal(t, tc.expectCode, w.Code)
			assert.Equal(t, tc.expectBody, w.Body.String())
		})
	}
}

func TestAuthRouter_getID(t *testing.T) {
	type args struct {
		ctx    context.Context
		access string
	}

	type mockBehaviour func(m *servicemocks.MockAuth, a args)

	testCases := []struct {
		testName      string
		args          args
		mockBehaviour mockBehaviour
		inputToken    string
		expectCode    int
		expectBody    string
	}{
		{
			testName: "correct test",
			args: args{
				ctx:    context.Background(),
				access: "ACCESS",
			},
			mockBehaviour: func(m *servicemocks.MockAuth, a args) {
				m.EXPECT().GetID(a.ctx, a.access).Return("USER", nil)
			},
			inputToken: "ACCESS",
			expectCode: http.StatusOK,
			expectBody: `{"user_id":"USER"}` + "\n",
		},
		{
			testName:      "missing token",
			inputToken:    "",
			mockBehaviour: func(m *servicemocks.MockAuth, a args) {},
			expectCode:    http.StatusUnauthorized,
		},
		{
			testName: "invalid token",
			args: args{
				ctx:    context.Background(),
				access: "INVALID_ACCESS",
			},
			mockBehaviour: func(m *servicemocks.MockAuth, a args) {
				m.EXPECT().GetID(a.ctx, a.access).Return("", service.ErrInvalidToken)
			},
			inputToken: "INVALID_ACCESS",
			expectCode: http.StatusForbidden,
		},
		{
			testName: "unexpected error",
			args: args{
				ctx:    context.Background(),
				access: "ACCESS",
			},
			mockBehaviour: func(m *servicemocks.MockAuth, a args) {
				m.EXPECT().GetID(a.ctx, a.access).Return("", errors.New("some error"))
			},
			inputToken: "ACCESS",
			expectCode: http.StatusInternalServerError,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.testName, func(t *testing.T) {
			ctrl := gomock.NewController(t)

			auth := servicemocks.NewMockAuth(ctrl)
			tc.mockBehaviour(auth, tc.args)

			e := echo.New()
			e.Validator = validator.NewValidator()
			NewRouter(e, &service.Services{Auth: auth})

			w := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodGet, "/api/v1/auth/me", nil)
			req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
			req.Header.Set(echo.HeaderAuthorization, "Bearer "+tc.inputToken)

			e.ServeHTTP(w, req)

			assert.Equal(t, tc.expectCode, w.Code)
			assert.Equal(t, tc.expectBody, w.Body.String())
		})
	}
}

func TestAuthRouter_logout(t *testing.T) {
	type args struct {
		ctx    context.Context
		access string
	}

	type mockBehaviour func(m *servicemocks.MockAuth, a args)

	testCases := []struct {
		testName      string
		args          args
		mockBehaviour mockBehaviour
		inputToken    string
		expectCode    int
	}{
		{
			testName: "correct test",
			args: args{
				ctx:    context.Background(),
				access: "ACCESS",
			},
			mockBehaviour: func(m *servicemocks.MockAuth, a args) {
				m.EXPECT().Logout(a.ctx, a.access).Return(nil)
			},
			inputToken: "ACCESS",
			expectCode: http.StatusOK,
		},
		{
			testName:      "missing token",
			mockBehaviour: func(m *servicemocks.MockAuth, a args) {},
			inputToken:    "",
			expectCode:    http.StatusUnauthorized,
		},
		{
			testName: "invalid token",
			args: args{
				ctx:    context.Background(),
				access: "INVALID_ACCESS",
			},
			mockBehaviour: func(m *servicemocks.MockAuth, a args) {
				m.EXPECT().Logout(a.ctx, a.access).Return(service.ErrInvalidToken)
			},
			inputToken: "INVALID_ACCESS",
			expectCode: http.StatusForbidden,
		},
		{
			testName: "unexpected error",
			args: args{
				ctx:    context.Background(),
				access: "ACCESS",
			},
			mockBehaviour: func(m *servicemocks.MockAuth, a args) {
				m.EXPECT().Logout(a.ctx, a.access).Return(errors.New("some error"))
			},
			inputToken: "ACCESS",
			expectCode: http.StatusInternalServerError,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.testName, func(t *testing.T) {
			ctrl := gomock.NewController(t)

			auth := servicemocks.NewMockAuth(ctrl)
			tc.mockBehaviour(auth, tc.args)

			e := echo.New()
			e.Validator = validator.NewValidator()
			NewRouter(e, &service.Services{Auth: auth})

			w := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodGet, "/api/v1/auth/logout", nil)
			req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
			req.Header.Set(echo.HeaderAuthorization, "Bearer "+tc.inputToken)

			e.ServeHTTP(w, req)

			assert.Equal(t, tc.expectCode, w.Code)
		})
	}
}
