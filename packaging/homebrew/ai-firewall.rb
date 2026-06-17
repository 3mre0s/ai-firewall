class AiFirewall < Formula
  desc "Local proxy that strips secrets from AI prompts before they reach any provider"
  homepage "https://github.com/torpilsiz/Ai-Firewall"
  version "0.1.0"
  license "AGPL-3.0-or-later"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/torpilsiz/Ai-Firewall/releases/download/v0.1.0/ai-firewall-darwin-arm64.tar.gz"
      sha256 "REPLACE_WITH_DARWIN_ARM64_SHA256"
    else
      url "https://github.com/torpilsiz/Ai-Firewall/releases/download/v0.1.0/ai-firewall-darwin-amd64.tar.gz"
      sha256 "REPLACE_WITH_DARWIN_AMD64_SHA256"
    end
  end

  on_linux do
    if Hardware::CPU.arm?
      url "https://github.com/torpilsiz/Ai-Firewall/releases/download/v0.1.0/ai-firewall-linux-arm64.tar.gz"
      sha256 "REPLACE_WITH_LINUX_ARM64_SHA256"
    else
      url "https://github.com/torpilsiz/Ai-Firewall/releases/download/v0.1.0/ai-firewall-linux-amd64.tar.gz"
      sha256 "REPLACE_WITH_LINUX_AMD64_SHA256"
    end
  end

  def install
    bin.install Dir["ai-firewall-*"].first => "ai-firewall"
  end

  test do
    assert_match "ai-firewall", shell_output("#{bin}/ai-firewall version")
  end
end
