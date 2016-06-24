require "spec_helper"
require "rotp"

class Important < Lita::Handler
  route /^unimportant$/, :unimportant, command: true, confirmation: { twofactor: 'block' }

  route /^danger$/, :danger, command: true, confirmation: { twofactor: 'allow' }

  route /^critical$/, :critical, command: true, confirmation: { twofactor: 'require' }

  route /^invalid$/, :critical, command: true, confirmation: { twofactor: 'foobar' }

  def unimportant(response)
    response.reply("Trivial command executed!")
  end

  def danger(response)
    response.reply("Important command executed!")
  end

  def critical(response)
    response.reply("Critical command executed!")
  end
end

describe Important, lita_handler: true do
  before do
    registry.register_handler(Lita::Handlers::Confirmation)
    registry.register_hook(:validate_route, Lita::Extensions::Confirmation)
    Lita::Extensions::Confirmation::UnconfirmedCommand.reset
  end

  it "does not accept invalid config values" do
    expect { send_command("invalid") }.to raise_error(RuntimeError, /not a valid value for Confirmation's twofactor option/)
  end

  context "with user not enrolled into 2fa" do
    it "does not allow routes that require 2fa" do
      send_command("critical")
      expect(replies.last).to match(/you have not set up two-factor authentication/)
    end

    it "lets the user enroll" do
      send_command("confirm 2fa enroll")
      expect(replies.last).to match(/Your secret code is [a-z0-9]{16}/)
    end

    it "lets the user opt out" do
      send_command("confirm 2fa remove")
      expect(replies.last).to match(/You will no longer be prompted/)
    end
  end

  context "with user enrolled into 2fa" do
    before do
      send_command("confirm 2fa enroll")
      code = /([a-z0-9]{16})/.match(replies.last).captures[0]
      @totp = ROTP::TOTP.new(code)
    end

    it "sends a 2fa prompt when allowed" do
      send_command("danger")
      expect(replies.last).to match(/YOUR_ONE_TIME_PASSWORD/)
    end

    it "invokes the original route on confirmation" do
      send_command("danger")
      code = replies.last.match(/\s([a-f0-9]{6})\s/)[1]
      send_command("confirm #{code} #{@totp.now}")
      expect(replies.last).to eq("Important command executed!")
    end

    it "requires the OTP" do
      send_command("danger")
      code = replies.last.match(/\s([a-f0-9]{6})\s/)[1]
      send_command("confirm #{code}")
      expect(replies.last).to match(/requires a one-time password in addition to the command code/)
    end

    it "does not accept correct OTP but invalid command code" do
      send_command("danger")
      code = ((replies.last.match(/\s([a-f0-9]{6})\s/)[1].to_i(16) + 1) % 0x1000000).to_s(16)
      send_command("confirm #{code} #{@totp.now}")
      expect(replies.last).to match(/is not a valid confirmation code/)
    end

    it "rejects an incorrect OTP" do
      send_command("danger")
      code = replies.last.match(/\s([a-f0-9]{6})\s/)[1]
      bad_otp = (@totp.now.to_i + 1) % 1000000
      send_command("confirm #{code} #{bad_otp}")
      expect(replies.last).to match(/one-time password you have provided is not correct/)
    end

    it "does not allow a non-enrolled user to confirm a 2fa prompt" do
      send_command("danger")
      code = replies.last.match(/\s([a-f0-9]{6})\s/)[1]
      manager = Lita::User.create(123)
      send_command("confirm #{code} 000000", as: manager)
      expect(replies.last).to match(/Please enroll in two-factor confirmation/)
    end
  end
end
