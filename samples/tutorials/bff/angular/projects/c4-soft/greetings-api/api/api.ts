export * from './get.service';
import { GetApi } from './get.service';
export * from './get.serviceInterface';
export * from './greetings.service';
import { GreetingsApi } from './greetings.service';
export * from './greetings.serviceInterface';
export const APIS = [GetApi, GreetingsApi];
