/**
 * Точный маршрут /workgemini — просто переиспользует общую реализацию,
 * чтобы логика пароля и форматов жила в одном файле.
 *
 * Вся работа в ./workgemini/[[path]].js (маршрут /workgemini/*).
 */
export { onRequest } from "./workgemini/[[path]].js";