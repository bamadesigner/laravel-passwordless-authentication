<?php

namespace NorbyBaru\Passwordless\Notifications;

use Illuminate\Bus\Queueable;
use Illuminate\Notifications\Messages\MailMessage;
use Illuminate\Notifications\Notification;
use Illuminate\Support\Facades\Lang;
use NorbyBaru\Passwordless\Facades\Passwordless;

class SendMagicLinkNotification extends Notification
{
    use Queueable;

    public function __construct(protected string $token)
    {
    }

    /**
     * Get the notification's channels.
     */
    public function via($notifiable): array|string
    {
        return ['mail'];
    }

    /**
     * Build the mail representation of the notification.
     */
    public function toMail($notifiable): MailMessage
    {
        return (new MailMessage)
            ->subject(Lang::get('Log in to :app_name', ['app_name' => config('app.name')]))
            ->line(Lang::get('Click the link below to log in to :app_name website.', ['app_name' => config('app.name')]))
            ->line(Lang::get('This link will expire in :count minutes and can only be used once.', ['count' => config('passwordless.magic_link_timeout')]))
            ->action(Lang::get('Log in to :app_name', ['app_name' => config('app.name')]), $this->verificationUrl($notifiable))
            ->line(Lang::get('If you did not request this login, no further action is required. If you have concerns or need help, reply to this email to contact us.'));
    }

    /**
     * Get the verification URL for the given notifiable.
     */
    protected function verificationUrl($notifiable): string
    {
        return Passwordless::magicLink()->generateUrl($notifiable, $this->token);
    }
}
