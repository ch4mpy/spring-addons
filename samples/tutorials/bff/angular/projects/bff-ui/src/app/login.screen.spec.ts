import { ComponentFixture, TestBed } from '@angular/core/testing';

import { LoginScreen } from './login.screen';

describe('LoginScreen', () => {
  let component: LoginScreen;
  let fixture: ComponentFixture<LoginScreen>;

  beforeEach(async () => {
    await TestBed.configureTestingModule({
      declarations: [ LoginScreen ]
    })
    .compileComponents();

    fixture = TestBed.createComponent(LoginScreen);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('should create', () => {
    expect(component).toBeTruthy();
  });
});
