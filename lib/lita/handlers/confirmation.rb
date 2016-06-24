require "rotp"

module Lita
  module Handlers
    class Confirmation < Handler
      # block - never use 2fa; allow; require - only allow 2fa
      config :twofactor_default, required: false, type: String, default: 'block'

      route /^confirm\s+([a-f0-9]{6})$/i, :confirm, command: true, help: {
        t("confirm_help.key") => t("confirm_help.value")
      }

      route /^confirm\s+([a-f0-9]{6})\s+([0-9]{6})$/i, :totp_confirm, command: true, help: {
        t("confirm_totp_help.key") => t("confirm_totp_help.value")
      }

      route /^confirm\s+2fa\s+enroll$/i,
        :enroll, command:true, help: { t("enroll_help.key") => t("enroll_help.value") }

      route /^confirm\s+2fa\s+remove$/i, :remove, command: true, help: {
        t("remove_help.key") => t("remove_help.value")
      }

      def confirm(response)
        code = response.matches[0][0]
        command = Extensions::Confirmation::UnconfirmedCommand.find(code)

        unless command
          response.reply(t("invalid_code", code: code))
          return
        end

        if command.twofactor
          response.reply(t("totp_not_provided"))
        else
          call_command(command, code, response)
        end
      end

      def totp_confirm(response)
        code = response.matches[0][0]
        command = Extensions::Confirmation::UnconfirmedCommand.find(code)

        unless command
          response.reply(t("invalid_code", code: code))
          return
        end

        totp_secret = redis.hget(response.user.id, "totp")
        unless totp_secret
          response.reply(t("totp_not_enrolled"))
          return
        end

        totp = ROTP::TOTP.new(totp_secret)
        # Attempting to 2FA verify a non-2FA confirmation is not a bad thing
        if totp.verify(response.matches[0][1]) || !command.twofactor
          call_command(command, code, response)
        else
          response.reply(t("totp_incorrect_otp"))
        end
      end

      def enroll(response)
        totp = ROTP::Base32.random_base32
        redis.hset(response.user.id, "totp", totp)

        response.reply(t("enrolled", totp: totp))
      end

      def remove(response)
        redis.hdel(response.user.id, 'totp')
        response.reply(t("removed"))
      end

      private

      def call_command(command, code, response)
        case command.call(response.user)
        when :other_user_required
          response.reply(t("other_user_required", code: code))
        when :user_in_group_required
          response.reply(
            t("user_in_group_required", code: code, groups: command.groups.join(", "))
          )
        end
      end
    end

    Lita.register_handler(Confirmation)
  end
end
