output "public_ip" {
  value = module.service.public_ip
}

output "private_key" {
  value = try(module.key_pair[0].private_key_pem, "")
}
