output "public_ip" {
  value = try(module.service[0].public_ip, "")
}

output "private_key" {
  value = try(module.key_pair[0].private_key_pem, "")
}
