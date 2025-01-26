cask "malimite" do
  version "1.1"
  sha256 "a74fd75844aedec13b523da6f8faaf9ec0c2a37027c4e372f74294ea07069528"

  url "https://github.com/LaurieWired/Malimite/releases/download/#{version}/Malimite-1-1.zip"
  name "Malimite"
  desc "iOS and macOS Decompiler"
  homepage "https://github.com/LaurieWired/Malimite"

  depends_on formula: "java"

  stage_only true

  postflight do
    libexec = "#{HOMEBREW_PREFIX}/libexec/malimite"
    bin = "#{HOMEBREW_PREFIX}/bin/malimite"

    # Move all files to libexec
    FileUtils.mkdir_p libexec
    FileUtils.mv Dir["#{staged_path}/*"], libexec

    # Symlink the existing shell script to the bin directory
    FileUtils.ln_sf "#{libexec}/malimite", bin
  end

  uninstall delete: [
    "#{HOMEBREW_PREFIX}/bin/malimite",
    "#{HOMEBREW_PREFIX}/libexec/malimite",
  ]

  caveats <<~EOS
    Ghidra is a recommended dependency for Malimite. You can install it via:
      brew install --cask ghidra
  EOS
end
