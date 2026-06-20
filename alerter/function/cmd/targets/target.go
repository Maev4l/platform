package targets

import "github.com/Maev4l/platform/notifications"

type Target interface {
	GetName() string
	SendAlert(alert *notifications.Message) error
}
