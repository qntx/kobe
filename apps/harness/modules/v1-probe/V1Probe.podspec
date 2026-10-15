require "json"

package = JSON.parse(File.read(File.join(__dir__, "package.json")))

Pod::Spec.new do |s|
  s.name         = "V1Probe"
  s.version      = package["version"]
  s.summary      = package["description"]
  s.homepage     = "https://github.com/qntx/wallet"
  s.license      = package["license"]
  s.authors      = package["author"]

  s.platforms    = { :ios => min_ios_version_supported }
  s.source       = { :git => "https://github.com/qntx/wallet.git" }

  s.source_files = [
    "cpp/**/*.{h,hpp,c,cpp}",
    "cpp/generated/**/*.{h,hpp,c,cpp}",
  ]

  s.pod_target_xcconfig = {
    "CLANG_CXX_LANGUAGE_STANDARD" => "c++20",
    "HEADER_SEARCH_PATHS" => [
      '"$(PODS_TARGET_SRCROOT)/cpp"',
      '"$(PODS_ROOT)/hermes-engine/destroot/include"',
    ].join(' '),
  }

  load 'nitrogen/generated/ios/V1Probe+autolinking.rb'
  add_nitrogen_files(s)

  s.dependency 'React-jsi'
  s.dependency 'React-callinvoker'
  s.dependency 'React-hermes'
  s.dependency 'hermes-engine'
  install_modules_dependencies(s)
end
