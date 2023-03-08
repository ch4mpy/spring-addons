import { ComponentFixture, TestBed } from '@angular/core/testing';

import { GreetingScreen } from './greeting.screen';

describe('HomeScreen', () => {
  let component: GreetingScreen;
  let fixture: ComponentFixture<GreetingScreen>;

  beforeEach(async () => {
    await TestBed.configureTestingModule({
      declarations: [ GreetingScreen ]
    })
    .compileComponents();

    fixture = TestBed.createComponent(GreetingScreen);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('should create', () => {
    expect(component).toBeTruthy();
  });
});
