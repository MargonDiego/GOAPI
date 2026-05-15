package application

import (
	"context"
	"testing"

	"github.com/diego/go-api/internal/domain"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

// mockAuditRepository es un mock manual para AuditRepository.
type mockAuditRepository struct {
	mock.Mock
}

func (m *mockAuditRepository) Log(ctx context.Context, log *domain.AuditLog) error {
	args := m.Called(ctx, log)
	return args.Error(0)
}

func TestWithActor(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	ctx = WithActor(ctx, 42)

	uid, ok := ActorFromContext(ctx)
	assert.True(t, ok)
	assert.Equal(t, uint(42), uid)
}

func TestActorFromContext_NotFound(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	uid, ok := ActorFromContext(ctx)
	assert.False(t, ok)
	assert.Equal(t, uint(0), uid)
}

func TestAuditService_log_WithActor(t *testing.T) {
	t.Parallel()

	mockRepo := new(mockAuditRepository)
	svc := newAuditService(mockRepo)

	ctx := WithActor(context.Background(), 7)

	mockRepo.On("Log", mock.Anything, mock.MatchedBy(func(log *domain.AuditLog) bool {
		return log.Action == "create_role" &&
			log.ActorID == 7 &&
			log.TargetType == "role" &&
			log.TargetID == 1
	})).Return(nil)

	svc.log(ctx, "create_role", "role", 1, nil, map[string]any{"name": "Admin"})

	mockRepo.AssertExpectations(t)
}

func TestAuditService_log_WithoutActor(t *testing.T) {
	t.Parallel()

	mockRepo := new(mockAuditRepository)
	svc := newAuditService(mockRepo)

	ctx := context.Background()

	// Sin actor no debe llamar al repo.
	svc.log(ctx, "create_role", "role", 1, nil, map[string]any{"name": "Admin"})

	mockRepo.AssertNotCalled(t, "Log")
}

func TestAuditService_log_NilRepo(t *testing.T) {
	t.Parallel()

	svc := newAuditService(nil)
	ctx := WithActor(context.Background(), 7)

	// No debe panicar ni fallar.
	assert.NotPanics(t, func() {
		svc.log(ctx, "create_role", "role", 1, nil, map[string]any{"name": "Admin"})
	})
}
