import { NgModule } from '@angular/core';
import { RouterModule, Routes } from '@angular/router';
import { GreetingScreen } from './greeting.screen';
import { LoginScreen } from './login.screen';

const routes: Routes = [
  { path: '', component: GreetingScreen },
  { path: 'login', component: LoginScreen },
];

@NgModule({
  imports: [RouterModule.forRoot(routes)],
  exports: [RouterModule],
})
export class AppRoutingModule {}
