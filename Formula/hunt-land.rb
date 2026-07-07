# Homebrew formula — this repo doubles as a tap:
#   brew tap r-sandy/hunt-land https://github.com/r-sandy/hunt-land
#   brew install hunt-land
#
# Installs from the tagged git revision. Once release tarballs exist you can
# switch `url` to the .tar.gz + sha256 form (the release workflow prints the
# sha256 for each tag).
class HuntLand < Formula
  desc "Living-off-the-Land forensic hunter for Blue Team defenders"
  homepage "https://github.com/r-sandy/hunt-land"
  url "https://github.com/r-sandy/hunt-land.git", tag: "v1.0.1"
  version "1.0.1"
  license "MIT"

  def install
    bin.install Dir["tools/bin/hunt-*"]
    (lib/"hunt-land").install "tools/lib/hunt-common.sh"
  end

  test do
    assert_match "Living-off-the-Land", shell_output("#{bin}/hunt-land --help")
  end
end
