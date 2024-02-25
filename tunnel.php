#!/usr/bin/env php
<?php

cli_set_process_title("php-gre-tunnel");
require_once(__DIR__ . "/src/GRE.php");

function main(int $argc, array $argv): void {

  strcmp(PHP_OS, "Linux") == 0 or shutdown(1, "Must run on Linux.");
  posix_getuid() == 0 or shutdown(1, "Must run as root.");

  $argv = parse_argv($argc, $argv);
  $local_socket  = prepare_local_socket($argv["local"]);
  $remote_socket = prepare_remote_socket($argv["remote"]);

  $pid = pcntl_fork();
  if ($pid > 0) {
    forward_remote_packets($local_socket, $remote_socket);
  } else if ($pid == 0) {
    forward_local_packets($local_socket, $remote_socket);
  }

}

function prepare_local_socket(string $local): Socket {

  file_exists($local) && unlink($local);

  $socket = socket_create(AF_UNIX, SOCK_RAW, 0);
  if ($socket === false || !socket_bind($socket, $local)) {
    shutdown(1, socket_strerror(socket_last_error()));
  }

  return $socket;

}

function prepare_remote_socket(string $remote): Socket {

  $socket = socket_create(AF_INET, SOCK_RAW, 47);
  if ($socket === false || !socket_connect($socket, $remote, 0)) {
    shutdown(1, socket_strerror(socket_last_error()));
  }

  return $socket;

}

function forward_local_packets(Socket $local_socket, Socket $remote_socket): void {

  while (socket_recv($local_socket, $buffer, 65535, 0)) {
    print_terminal(strlen($buffer) . " bytes received from local socket.");

    $gre_header = new GRE\header();
    $gre_header->payload = $buffer;

    print_gre_header($gre_header);
    $packet = GRE\pack_header($gre_header);
    socket_send($remote_socket, $packet, strlen($packet), 0);

  }

}

function forward_remote_packets(Socket $local_socket, Socket $remote_socket): void {

  while (socket_recv($remote_socket, $buffer, 65535, 0)) {
    print_terminal(strlen($buffer) . " bytes received from remote peer.");

    $buffer = substr($buffer, 20);
    $gre_header = GRE\unpack_header($buffer);

    print_gre_header($gre_header);
    $payload = $gre_header->payload;
    socket_send($local_socket, $payload, strlen($payload), 0);

  }

}

function parse_argv(int $argc, array $argv): array {

  $parsed_argv = [];
  for ($i = 0; $i < $argc; $i++) {
    $key = trim(strtolower($argv[$i]));
    if (in_array($key, [ "remote", "local" ])) {
      $parsed_argv[$key] = $argv[++$i];
    }
  }

  return $parsed_argv;

}

function print_gre_header(GRE\header $gre_header): void {
  $gre_proto_type = $gre_header->protocol_type;
  $gre_payload = $gre_header->payload;
  print_terminal(sprintf("GRE protocol type: %04x", $gre_proto_type));
  print_terminal(sprintf("GRE payload length: %d", strlen($gre_payload)));
}

function print_terminal(string $expression, string $terminal = "/dev/tty"): void {
  file_put_contents($terminal,
    sprintf("[%s]\t%s\r\n", microtime(), $expression)
  );
}

function shutdown(bool $by_error, string $message): void {
  print_terminal($message);
  exit((int)$by_error);
}

main($_SERVER["argc"], $_SERVER["argv"]);
