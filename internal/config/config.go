package config

import (
	"log"
	"time"

	"github.com/spf13/viper"
)

type Config struct {
	JWT struct {
		AccessSecret  string        `mapstructure:"access_secret"`
		RefreshSecret string        `mapstructure:"refresh_secret"`
		AccessExpiry  time.Duration `mapstructure:"access_expiry"`
		RefreshExpiry time.Duration `mapstructure:"refresh_expiry"`
	}
	Database struct {
		Host     string `mapstructure:"host"`
		Port     string `mapstructure:"port"`
		User     string `mapstructure:"user"`
		Password string `mapstructure:"password"`
		DBName   string `mapstructure:"db_name"`
	}
	Redis struct {
		Addr        string        `mapstructure:"addr"`
		Password    string        `mapstructure:"password"`
		User        string        `mapstructure:"user"`
		DB          int           `mapstructure:"db"`
		MaxRetries  int           `mapstructure:"max_retries"`
		DialTimeout time.Duration `mapstructure:"dial_timeout"`
		Timeout     time.Duration `mapstructure:"timeout"`
	}
	Server struct {
		HTTPPort string `mapstructure:"http_port"`
		GRPCPort string `mapstructure:"grpc_port"`
	}
	Keycloak struct {
		Url          string   `mapstructure:"url"`
		ClientID     string   `mapstructure:"client_id"`
		ClientSecret string   `mapstructure:"client_secret"`
		Scopes       []string `mapstructure:"scopes"`
	}
	DataProcessor struct {
		Address string `mapstructure:"address"`
		Port    string `mapstructure:"port"`
	} `mapstructure:"data_processor"`
}

func Load() *Config {
	viper.SetConfigName("config") // имя файла (без расширения)
	viper.SetConfigType("yaml")   // или json
	viper.AddConfigPath("./")
	viper.AddConfigPath(".") // ищем в текущей директории

	if err := viper.ReadInConfig(); err != nil {
		log.Fatalf("Error reading config: %v", err)
	}

	var cfg Config
	if err := viper.Unmarshal(&cfg); err != nil {
		log.Fatalf("Unable to decode config: %v", err)
	}

	return &cfg
}
