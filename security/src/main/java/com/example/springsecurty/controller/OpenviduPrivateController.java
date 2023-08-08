package com.example.springsecurty.controller;


import io.openvidu.java.client.*;
import java.util.Map;
import javax.annotation.PostConstruct;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequiredArgsConstructor
@RequestMapping("/api/v1/openvidu")
public class OpenviduPrivateController {

    @Value("${open.url}")
    private String OPENVIDU_URL;

    @Value("${open.secret}")
    private String OPENVIDU_SECRET;

    private OpenVidu openvidu;

    @PostConstruct
    public void init() {
        this.openvidu = new OpenVidu(OPENVIDU_URL, OPENVIDU_SECRET);
    }

    /**
     * @param params The Session properties
     * @return The Session ID
     */
    @PostMapping("/sessions")
    public ResponseEntity<String> initializeSession(@RequestBody(required = false) Map<String, Object> params)
            throws OpenViduJavaClientException, OpenViduHttpException {
        SessionProperties properties = SessionProperties.fromJson(params).build();
        Session session = openvidu.createSession(properties);

        // 방이 만들어지면서 fcm 알림을 보내주면 될듯
        // fcmService.sendMessages(Long.parseLong(session.getSessionId()));

        return new ResponseEntity<>(session.getSessionId(), HttpStatus.OK);
    }

    /**
     * @param sessionId The Session in which to create the Connection
     * @param params    The Connection properties
     * @return The Token associated to the Connection
     */
    @PostMapping("{sessionId}/connections")
    public ResponseEntity<String> createConnection(@PathVariable("sessionId") String sessionId,
            @RequestBody(required = false) Map<String, Object> params)
            throws OpenViduJavaClientException, OpenViduHttpException {
        Session session = openvidu.getActiveSession(sessionId);
        if (session == null) {
            return new ResponseEntity<>(HttpStatus.NOT_FOUND);
        }
        ConnectionProperties properties = ConnectionProperties.fromJson(params).build();
        Connection connection = session.createConnection(properties);

        System.out.println(connection.getToken());
        return new ResponseEntity<>(connection.getToken(), HttpStatus.OK);
    }

// 알람을 받으면 바로 connections 실행할 수 있게 해주면 됨, 이거 써야됨 위에꺼는 openvidu랑 연결 잘되는지 확인할려고 쓰고 있음
//    /**
//     * @return The Token associated to the Connection
//     */
//    @PostMapping("/connections")
//    public ResponseEntity<String> createConnection()
//            throws OpenViduJavaClientException, OpenViduHttpException {
//
//        Long sessionId = memberService.getClassId(SecurityUtil.getLoginUserId());
//
//        Session session = openvidu.getActiveSession(String.valueOf(sessionId));
//        if (session == null) {
//            return new ResponseEntity<>(HttpStatus.NOT_FOUND);
//        }
//        Connection connection = session.createConnection();
//
//        return new ResponseEntity<>(connection.getToken(), HttpStatus.OK);
//    }

}
