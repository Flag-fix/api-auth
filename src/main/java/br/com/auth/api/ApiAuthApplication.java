package br.com.auth.api;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
public class ApiAuthApplication {

	public static void main(String[] args) {
		SpringApplication.run(ApiAuthApplication.class, args);

		System.out.println();
		System.out.println("✨🚀 MS - AUTH 🚀✨");
		System.out.println("🔒 Secure Authentication Service 🔒");
		System.out.println("🌟 Ready to handle your users' authentication needs! 🌟");
		System.out.println("📖 Documentation: http://localhost:8080/docs");
		System.out.println();
	}
}